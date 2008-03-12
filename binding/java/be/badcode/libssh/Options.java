package be.badcode.libssh;

public class Options {
	long handle=0;
	static {
        System.loadLibrary("ssh_java");
    }
    private native long New();
    public Options(){
    	handle=New();
    }
    private Options(long h){
    	handle=h;
    }
    public void finalize(){
    	handle=0;
    }
    public Options copy(){
    	long h=doCopy();
    	return new Options(h);
    }
    public native long doCopy();
    public native int setWantedAlgos(int algos, String list);
    public native void setUsername(String username);
    public native void setPort(int port);
    public native int getopt(String args[]);
    public native void setHost(String host);
    public native void setBind(String host, int port);
    public native void setIdentity(String identityFile);
    public native void setTimeout(long seconds, long usecs);
    public native void setSshDir(String dir);
    public native void setKnownHostsFile(String file);
    public native void allowSsh1(boolean allow);
    public native void allowSsh2(boolean allow);
    public native void setDsaServerKey(String dsaKey);
    public native void setRsaServerKey(String rsaKey);
    
}
