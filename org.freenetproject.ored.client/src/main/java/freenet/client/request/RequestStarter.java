package freenet.client.request;

// TODO: Modularity: Make RequestStarter implement this and maybe rename it to NodeRequestStarter?
public interface RequestStarter extends Runnable, RandomGrabArrayItemExclusionList {
    void wakeUp();
}
