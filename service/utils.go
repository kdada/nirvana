/*
Copyright 2017 Caicloud Authors

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

package service

import (
	"context"
	"net/http"

	"github.com/caicloud/nirvana/errors"
)

// WarpHTTPHandler warps a http handler to definition function.
func WarpHTTPHandler(h http.Handler) func(ctx context.Context) {
	return func(ctx context.Context) {
		httpCtx := HTTPContextFrom(ctx)
		h.ServeHTTP(httpCtx.ResponseWriter(), httpCtx.Request())
	}
}

// WarpHTTPHandlerFunc warps a http handler func to definition function.
func WarpHTTPHandlerFunc(f http.HandlerFunc) func(ctx context.Context) {
	return func(ctx context.Context) {
		httpCtx := HTTPContextFrom(ctx)
		f(httpCtx.ResponseWriter(), httpCtx.Request())
	}
}

// Internel error factories:
var noExecutorForMethod = errors.MethodNotAllowed.Build("Nirvana:Service:NoExecutorForMethod", "method not allowed")
var noExecutorForContentType = errors.UnsupportedMediaType.Build("Nirvana:Service:NoExecutorForContentType", "unsupported media type")
var noExecutorToProduce = errors.NotAcceptable.Build("Nirvana:Service:NoExecutorToProduce", "not acceptable")
var invalidContentType = errors.BadRequest.Build("Nirvana:Service:InvalidContentType", "invalid content type ${type}")

var noRouter = errors.InternalServerError.Build("Nirvana:Service:NoRouter", "no router to build service")
var invalidService = errors.InternalServerError.Build("Nirvana:Service:NoResponse", "no response")
var invalidConversion = errors.InternalServerError.Build("Nirvana:Service:InvalidConversion", "can't convert ${data} to ${type}")
var invalidConsumer = errors.InternalServerError.Build("Nirvana:Service:InvalidConsumer", "${type} is invalid for consumer")
var invalidProducer = errors.InternalServerError.Build("Nirvana:Service:InvalidProducer", "${type} is invalid for producer")
var noConnectionHijacker = errors.InternalServerError.Build("Nirvana:Service:NoConnectionHijacker",
	"underlying http.ResponseWriter does not implement http.Hijacker")
var definitionNoMethod = errors.InternalServerError.Build("Nirvana:Service:DefinitionNoMethod", "no http method in [${method}]${path}")
var definitionNoComsumes = errors.InternalServerError.Build("Nirvana:Service:DefinitionNoComsumes", "no content type to consume in [${method}]${path}")
var definitionNoProduces = errors.InternalServerError.Build("Nirvana:Service:DefinitionNoProduces", "no content type to produce in [${method}]${path}")
var definitionNoFunction = errors.InternalServerError.Build("Nirvana:Service:DefinitionNoFunction", "no function in [${method}]${path}")
var definitionInvalidFunctionType = errors.InternalServerError.Build("Nirvana:Service:DefinitionInvalidFunctionType",
	"${type} is not function in [${method}]${path}")
var definitionNoComsumer = errors.InternalServerError.Build("Nirvana:Service:DefinitionNoComsumer",
	"no consumer for content type ${type} in [${method}]${path}")
var definitionNoProducer = errors.InternalServerError.Build("Nirvana:Service:DefinitionNoProducer",
	"no producer for content type ${type} in [${method}]${path}")
var definitionConflict = errors.InternalServerError.Build("Nirvana:Service:DefinitionConflict",
	"consumer-producer pair ${key}:${value} conflicts in [http.${method}]${path}")
var definitionUnmatchedParameters = errors.InternalServerError.Build("Nirvana:Service:DefinitionUnmatchedParameters",
	"function ${function} has ${count} parameters but want ${desired} in ${path}")
var definitionUnmatchedResults = errors.InternalServerError.Build("Nirvana:Service:DefinitionUnmatchedResults",
	"function ${function} has ${count} results but want ${desired} in ${path}")
var noDestinationHandler = errors.InternalServerError.Build("Nirvana:Service:NoDestinationHandler", "no destination handler for destination ${destination}")
var noContext = errors.InternalServerError.Build("Nirvana:Service:NoContext", "can't find http context")
var requiredField = errors.InternalServerError.Build("Nirvana:Service:RequiredField", "required field ${field} in ${source} but got empty")
var invalidMetaType = errors.InternalServerError.Build("Nirvana:Service:InvalidMetaType", "can't recognize meta for type ${type}")
var noProducerToWrite = errors.NotAcceptable.Build("Nirvana:Service:NoProducerToWrite", "can't find producer for accept types ${types}")
var invalidMethod = errors.InternalServerError.Build("Nirvana:Service:InvalidMethod", "http method ${method} is invalid")
var invalidStatusCode = errors.InternalServerError.Build("Nirvana:Service:InvalidStatusCode", "http status code must be in [100,599]")
var unassignableType = errors.InternalServerError.Build("Nirvana:Service:UnassignableType", "type ${typeA} can't assign to ${typeB}")
var noConverter = errors.InternalServerError.Build("Nirvana:Service:UnassignableType", "no converter for type ${type}")
var invalidBodyType = errors.InternalServerError.Build("Nirvana:Service:InvalidBodyType", "${type} is not a valid type for body")
var noPrefab = errors.InternalServerError.Build("Nirvana:Service:NoPrefab", "no prefab named ${name}")
var invalidAutoParameter = errors.InternalServerError.Build("Nirvana:Service:InvalidAutoParameter", "${type} is not a struct or a pointer to struct")
var noParameterGenerator = errors.InternalServerError.Build("Nirvana:Service:NoParameterGenerator", "no parameter generator for source ${source}")
var invalidFieldTag = errors.InternalServerError.Build("Nirvana:Service:InvalidFieldTag", "filed tag ${tag} is invalid")