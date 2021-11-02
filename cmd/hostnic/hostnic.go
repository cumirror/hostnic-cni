//
// =========================================================================
// Copyright (C) 2020 by Yunify, Inc...
// -------------------------------------------------------------------------
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this work except in compliance with the License.
// You may obtain a copy of the License in the LICENSE file, or at:
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// =========================================================================
//

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"runtime"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
	"github.com/davecgh/go-spew/spew"
	"github.com/j-keck/arping"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	ipam2 "github.com/yunify/hostnic-cni/cmd/hostnic/ipam"
	constants "github.com/yunify/hostnic-cni/pkg/constants"
	"github.com/yunify/hostnic-cni/pkg/log"
	"github.com/yunify/hostnic-cni/pkg/networkutils"
)

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

func createMacvlan(master, ifName string, mtu int, netns ns.NetNS) (*current.Interface, error) {
	macvlan := &current.Interface{}

	m, err := netlink.LinkByName(master)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup master %q: %v", master, err)
	}

	// due to kernel bug we have to create with tmpName or it might
	// collide with the name on the host and error out
	tmpName, err := ip.RandomVethName()
	if err != nil {
		return nil, err
	}

	linkAttrs := netlink.LinkAttrs{
		MTU:         mtu,
		Name:        tmpName,
		ParentIndex: m.Attrs().Index,
		Namespace:   netlink.NsFd(int(netns.Fd())),
	}

	mv := &netlink.Macvlan{
		LinkAttrs: linkAttrs,
		Mode:      netlink.MACVLAN_MODE_BRIDGE,
	}

	if err := netlink.LinkAdd(mv); err != nil {
		return nil, fmt.Errorf("failed to create macvlan: %v", err)
	}

	err = netns.Do(func(_ ns.NetNS) error {
		err := ip.RenameLink(tmpName, ifName)
		if err != nil {
			_ = netlink.LinkDel(mv)
			return fmt.Errorf("failed to rename macvlan to %q: %v", ifName, err)
		}
		macvlan.Name = ifName

		// Re-fetch macvlan to get all properties/attributes
		contMacvlan, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("failed to refetch macvlan %q: %v", ifName, err)
		}
		macvlan.Mac = contMacvlan.Attrs().HardwareAddr.String()
		macvlan.Sandbox = netns.Path()

		return nil
	})
	if err != nil {
		return nil, err
	}

	return macvlan, nil
}

func checkConf(conf *constants.NetConf) error {
	if conf.LogLevel == 0 {
		conf.LogLevel = int(logrus.InfoLevel)
	}
	log.Setup(&log.LogOptions{
		Level: conf.LogLevel,
		File:  conf.LogFile,
	})

	if conf.HostVethPrefix == "" {
		conf.HostVethPrefix = constants.HostNicPrefix
	}

	if conf.MTU == 0 {
		conf.MTU = 1500
	}

	if conf.HostNicType != constants.HostNicPassThrough {
		conf.HostNicType = constants.HostNicVeth
	}

	if conf.RT2Pod == 0 {
		conf.RT2Pod = constants.MainTable
	}

	if conf.Interface == "" {
		conf.Interface = constants.DefaultPrimaryNic
	}

	if conf.NatMark == "" {
		conf.NatMark = constants.DefaultNatMark
	}

	return nil
}

func cmdAdd(args *skel.CmdArgs) error {
	var err error

	logrus.Infof("cmdAdd args %v", args)
	defer func() {
		logrus.Infof("cmdAdd for %s rst: %v", args.ContainerID, err)
	}()

	conf := constants.NetConf{}
	if err = json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf %s: %v", spew.Sdump(args), err)
	}
	if err = checkConf(&conf); err != nil {
		return err
	}

	// run the IPAM plugin and get back the config to apply
	ipamMsg, rst, err := ipam2.AddrAlloc(args)
	if err != nil {
		return fmt.Errorf("failed to alloc addr: %v", err)
	}
	podInfo := ipamMsg.Args
	// podInfo.NicType is from annotation
	conf.HostNicType = podInfo.NicType

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	macvlanInterface, err := createMacvlan(constants.GetHostNicName(ipamMsg.Nic.VxNet.ID), args.IfName, conf.MTU, netns)
	if err != nil {
		return err
	}

	// Delete link if err to avoid link leak in this ns
	defer func() {
		if err != nil {
			netns.Do(func(_ ns.NetNS) error {
				return ip.DelLinkByName(args.IfName)
			})
		}
	}()

	// Assume L2 interface only
	result := &current.Result{
		CNIVersion: conf.CNIVersion,
		Interfaces: []*current.Interface{macvlanInterface},
	}

	result.IPs = rst.IPs
	result.Routes = rst.Routes

	for _, ipc := range result.IPs {
		// All addresses apply to the container macvlan interface
		ipc.Interface = current.Int(0)
	}

	err = netns.Do(func(_ ns.NetNS) error {
		if err := ipam.ConfigureIface(args.IfName, result); err != nil {
			return err
		}

		contVeth, err := net.InterfaceByName(args.IfName)
		if err != nil {
			return fmt.Errorf("failed to look up %q: %v", args.IfName, err)
		}

		for _, ipc := range result.IPs {
			if ipc.Address.IP.To4() != nil {
				_ = arping.GratuitousArpOverIface(ipc.Address.IP, *contVeth)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return types.PrintResult(result, conf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	var err error

	logrus.Infof("cmdDel args %v", args)
	defer func() {
		logrus.Infof("cmdDel for %s rst: %v", args.ContainerID, err)
	}()

	conf := constants.NetConf{}
	if err = json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}
	if err = checkConf(&conf); err != nil {
		return err
	}

	_, err = ipam2.AddrUnalloc(args, true)
	if err != nil {
		if err == constants.ErrNicNotFound {
			return nil
		}
		return err
	}

	// There is a netns so try to clean up. Delete can be called multiple times
	// so don't return an error if the device is already removed.
	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		if err := ip.DelLinkByName(args.IfName); err != nil {
			if err != ip.ErrLinkNotFound {
				return err
			}
		}
		return nil
	})

	return err
}

func main() {
	networkutils.SetupNetworkHelper()
	skel.PluginMain(cmdAdd, nil, cmdDel, version.All, bv.BuildString("hostnic"))
}
