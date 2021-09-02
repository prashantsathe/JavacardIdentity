package com.android.se.ready;

public class ICByteBlob {
	private byte[] buffer;
	private short startOff;
	private short length;
	
	public ICByteBlob (byte[] buffer, short startOff, short length) {
		this.buffer = buffer;
		this.startOff = startOff;
		this.length = length;
	}
	
	byte[] getBuffer() {
		return buffer;
	}
	
	short getStartOff() {
		return startOff;
	}
	
	short getLength() {
		return length;
	}
}
