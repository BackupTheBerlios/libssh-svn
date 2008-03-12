package be.badcode.libssh;

public class SSHSession {
    static {
        System.loadLibrary("ssh_java");
    }
    public native void hello();
}

