package be.badcode.libssh;
public class Session {
	long handle=0;
    static {
        System.loadLibrary("ssh_java");
    }
    public Session(){
    	handle=New();
    }
    private native long New();
    public native int connect();
    public native void disconnect();
    public native String getIssueBanner();
    public native byte[] getPubkeyHash();
    public native int fdPoll(int write, int except);
    public native int select();
    public native int isServerKnown();
    public native int writeKnownhost();
    
    public native int userauthNone(String username);
    public native int userauthPassword(String username, String password);
    public native int userauthOfferPubkey(String username, String password, int type, String pubkey);
    public native int userauthPubkey(String username, String password, String pubkey, String privatekey);
    public native int userauthAutoPubkey();
    public native int userauthKbdint(String username, String submethods);
    public native int userauthKbdintGetnprompts();
    public native String userauthKbdintGetname();
    public native String userauthKbdintGetinstruction();
    public native String userauthKbdintGetprompt();
    public native void userauthKbdintSetanswer(int i, String ans);
}

