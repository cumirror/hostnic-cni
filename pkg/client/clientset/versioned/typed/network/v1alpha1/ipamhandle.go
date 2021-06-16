/*
Copyright 2020 The KubeSphere Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	"time"

	v1alpha1 "github.com/yunify/hostnic-cni/pkg/apis/network/v1alpha1"
	scheme "github.com/yunify/hostnic-cni/pkg/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// IPAMHandlesGetter has a method to return a IPAMHandleInterface.
// A group's client should implement this interface.
type IPAMHandlesGetter interface {
	IPAMHandles() IPAMHandleInterface
}

// IPAMHandleInterface has methods to work with IPAMHandle resources.
type IPAMHandleInterface interface {
	Create(ctx context.Context, iPAMHandle *v1alpha1.IPAMHandle, opts v1.CreateOptions) (*v1alpha1.IPAMHandle, error)
	Update(ctx context.Context, iPAMHandle *v1alpha1.IPAMHandle, opts v1.UpdateOptions) (*v1alpha1.IPAMHandle, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.IPAMHandle, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.IPAMHandleList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.IPAMHandle, err error)
	IPAMHandleExpansion
}

// iPAMHandles implements IPAMHandleInterface
type iPAMHandles struct {
	client rest.Interface
}

// newIPAMHandles returns a IPAMHandles
func newIPAMHandles(c *NetworkV1alpha1Client) *iPAMHandles {
	return &iPAMHandles{
		client: c.RESTClient(),
	}
}

// Get takes name of the iPAMHandle, and returns the corresponding iPAMHandle object, and an error if there is any.
func (c *iPAMHandles) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.IPAMHandle, err error) {
	result = &v1alpha1.IPAMHandle{}
	err = c.client.Get().
		Resource("ipamhandles").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of IPAMHandles that match those selectors.
func (c *iPAMHandles) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.IPAMHandleList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.IPAMHandleList{}
	err = c.client.Get().
		Resource("ipamhandles").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested iPAMHandles.
func (c *iPAMHandles) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("ipamhandles").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a iPAMHandle and creates it.  Returns the server's representation of the iPAMHandle, and an error, if there is any.
func (c *iPAMHandles) Create(ctx context.Context, iPAMHandle *v1alpha1.IPAMHandle, opts v1.CreateOptions) (result *v1alpha1.IPAMHandle, err error) {
	result = &v1alpha1.IPAMHandle{}
	err = c.client.Post().
		Resource("ipamhandles").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(iPAMHandle).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a iPAMHandle and updates it. Returns the server's representation of the iPAMHandle, and an error, if there is any.
func (c *iPAMHandles) Update(ctx context.Context, iPAMHandle *v1alpha1.IPAMHandle, opts v1.UpdateOptions) (result *v1alpha1.IPAMHandle, err error) {
	result = &v1alpha1.IPAMHandle{}
	err = c.client.Put().
		Resource("ipamhandles").
		Name(iPAMHandle.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(iPAMHandle).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the iPAMHandle and deletes it. Returns an error if one occurs.
func (c *iPAMHandles) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("ipamhandles").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *iPAMHandles) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("ipamhandles").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched iPAMHandle.
func (c *iPAMHandles) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.IPAMHandle, err error) {
	result = &v1alpha1.IPAMHandle{}
	err = c.client.Patch(pt).
		Resource("ipamhandles").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
