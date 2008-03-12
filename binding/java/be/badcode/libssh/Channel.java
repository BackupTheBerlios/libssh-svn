package be.badcode.libssh;
public class Channel {
	long handle=0;
	static {
        System.loadLibrary("ssh_java");
    }
    private native long New();
    private native void free();
    public Channel(){
    	handle=New();
    }
    public void finalize(){
    	free();
    	handle=0;
    }
    public int openForward(String remotehost, int remoteport){
    	return openForward(remotehost,remoteport,null,0);
    }
    public native int openForward(String remotehost, int remoteport, String localhost, int localport);
    public native int openSession();
    public native int requestPty();
    public native int requestPtySize(String term, int cols, int rows);
    public native int changePtySize(int cols, int rows);
    public native int requestShell();
    public native int requestSubsystem(String subsystem);
    public native int requestEnv(String env, String value);
    public native int requestExec(String command);
    public native int requestSftp();
    public native int write(byte buffer[]);
    public native int sendEof();
    public native boolean isEof();
    public native byte[] read(int len, boolean is_stderr);
    public native int poll(boolean is_stderr);
    public native int close();
    public native byte[] readNonblocking(int len, boolean is_stderr);
    public native boolean isOpen();
    public native boolean isClosed();
    public native int select(Channel[] readchans, Channel[] writechans, Channel[] exceptchans, long timeout);
    

}
