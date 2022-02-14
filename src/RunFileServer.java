import fileserver.FileServer;

/* Driver program for FileSharing File Server */
public class RunFileServer {

    public static void main(String[] args) {
        if (args.length > 0) {
            try {
                FileServer server = new FileServer(Integer.parseInt(args[0]));
                server.start();
            } catch (NumberFormatException e) {
                System.out.println("Enter a valid port number or pass no arguments to use a random port");
            }
        } else {
            int port = 9090;
            System.out.println("Starting server on port: " + port);
            FileServer server = new FileServer(port);
            server.start();
        }
    }

}
