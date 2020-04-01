package org.ll.auth.processor.feign;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;

import org.ll.auth.annotation.feign.LLRequestBody;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.openfeign.AnnotatedParameterProcessor;
import org.springframework.http.MediaType;
import org.springframework.util.StringUtils;

import com.alibaba.fastjson.JSON;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import feign.MethodMetadata;
import feign.Param;
import feign.Param.Expander;
import feign.Request.Body;
import feign.Util;
import feign.template.UriUtils;

public class RequestBodyParameterProcessor implements
		AnnotatedParameterProcessor {

	private static final Logger log = LoggerFactory.getLogger(RequestBodyParameterProcessor.class);
	private static final boolean isDebug = log.isDebugEnabled();
	
	private static final Class<LLRequestBody> ANNOTATION = LLRequestBody.class;
	
	@Override
	public Class<? extends Annotation> getAnnotationType() {
		return ANNOTATION;
	}

	@Override
	public boolean processArgument(AnnotatedParameterContext context,
			Annotation annotation, Method method) {
		int parameterIndex = context.getParameterIndex();
		Class<?> parameterType = method.getParameterTypes()[parameterIndex];
		MethodMetadata data = context.getMethodMetadata();

		String name = ANNOTATION.cast(annotation).value();
		String existingBody = data.template().requestBody().bodyTemplate();
		String leftCurlyBrace = UriUtils.encode("{", Util.UTF_8);
		String rightCurlyBrace = UriUtils.encode("}", Util.UTF_8);
		
		data.bodyIndex(null);
		StringBuilder appendBody = new StringBuilder();
		if(StringUtils.hasLength(existingBody)){
			appendBody.append(existingBody.substring(0, existingBody.length() - rightCurlyBrace.length())).append(", ") ;
		}else{
			appendBody.append(leftCurlyBrace);
		}
		
        nameParam(data, name, parameterIndex);
        if(isDebug){
        	log.debug("parameterType:" + parameterType);
        }
        
        appendBody.append(" \""+name+"\" : ");
        String jsonValue = "{" + name + "}";
        if(String.class.isAssignableFrom(parameterType)){
			data.indexToExpanderClass().put(parameterIndex, Param.ToStringExpander.class);
			appendBody.append("\"").append(jsonValue).append("\"");
		}else if(Collection.class.isAssignableFrom(parameterType)){
			data.indexToExpander().put(parameterIndex, jsonExpander);
			appendBody.append("[").append(jsonValue).append("]");
		}else{
			data.indexToExpander().put(parameterIndex, jsonExpander);
			appendBody.append(jsonValue);
		}
		appendBody.append(rightCurlyBrace);
		
		data.indexToEncoded().put(parameterIndex, false);
		if(isDebug){
			log.debug("parameterIndex:" + parameterIndex);
			log.debug("appendBody:" + appendBody);
		}
		data.template().body(Body.bodyTemplate(appendBody.toString(), Util.UTF_8));
		data.template().header("Content-type", MediaType.APPLICATION_JSON_UTF8_VALUE);
		return true;
	}
	
	
	private Expander jsonExpander = JSON::toJSONString;
	
	private void nameParam(MethodMetadata data, String name, int i) {
	      Collection<String> names =
	          data.indexToName().containsKey(i) ? data.indexToName().get(i) : new ArrayList<String>();
	      names.add(name);
	      data.indexToName().put(i, names);
	}

}
