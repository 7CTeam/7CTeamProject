package com.istrom.po;

import java.io.Serializable;
/**
 * ajax请求返回数据封装
 */
public class Result implements Serializable {

	private static final long serialVersionUID = 1L;

	private String info;//消息
	
	private Object data;//数据
	
	private int status;//状态

	public String getInfo() {
		return info;
	}

	public void setInfo(String info) {
		this.info = info;
	}

	public Object getData() {
		return data;
	}

	public void setData(Object data) {
		this.data = data;
	}

	public int getStatus() {
		return status;
	}

	public void setStatus(int status) {
		this.status = status;
	}

	@Override
	public String toString() {
		return "Result [info=" + info + ", data=" + data + ", status=" + status + "]";
	}
}
