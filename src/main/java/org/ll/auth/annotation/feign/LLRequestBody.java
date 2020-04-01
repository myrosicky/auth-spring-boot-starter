package org.ll.auth.annotation.feign;

import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

@Retention(RUNTIME)
@Target(PARAMETER)
public @interface LLRequestBody {

	  /**
	   * The name of the template parameter.
	   */
	  String value();

}
