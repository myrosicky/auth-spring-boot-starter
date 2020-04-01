package org.ll.auth.exception;

import org.springframework.util.StringUtils;

public class AppException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	private String errCode;
	private String errMsg;
	
	public AppException() {
		super();
	}
	public AppException(String errCode, String errMsg, Throwable cause,
			boolean enableSuppression, boolean writableStackTrace) {
		super(produceMessage(errCode, errMsg), cause, enableSuppression, writableStackTrace);
		this.errCode = errCode;
		this.errMsg = errMsg;
	}
	public AppException(String errCode, String errMsg, Throwable cause) {
		super(produceMessage(errCode, errMsg), cause);
		this.errCode = errCode;
		this.errMsg = errMsg;
	}
	public AppException(String errCode, String errMsg) {
		super(produceMessage(errCode, errMsg));
		this.errCode = errCode;
		this.errMsg = errMsg;
	}
	public AppException(String errCode) {
		super(produceMessage(errCode, null));
		this.errCode = errCode;
	}
	public AppException(Throwable cause) {
		super(cause);
	}
	
	public String getErrCode() {
		return errCode;
	}
	public void setErrCode(String errCode) {
		this.errCode = errCode;
	}
	public String getErrMsg() {
		return errMsg;
	}
	public void setErrMsg(String errMsg) {
		this.errMsg = errMsg;
	}
	private static String produceMessage(String errCode, String errMsg){
		if(StringUtils.isEmpty(errCode)){
			return null;
		}
		
		return "[" + errCode + "]" + errMsg;
	}
	
}
