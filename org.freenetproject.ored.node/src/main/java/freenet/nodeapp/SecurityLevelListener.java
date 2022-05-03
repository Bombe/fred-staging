package freenet.nodeapp;

public interface SecurityLevelListener<T> {
	
	public void onChange(T oldLevel, T newLevel);

}
