package freenet.nodeapp;

public interface DecodingMessageGroup {
	
	void processDecryptedMessage(byte[] data, int offset, int length, int overhead);
	
	void complete();

}
