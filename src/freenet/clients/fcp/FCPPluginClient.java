/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.clients.fcp;

import java.io.IOException;
import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import freenet.node.NodeStarter;
import freenet.node.PrioRunnable;
import freenet.pluginmanager.FredPluginFCPMessageHandler;
import freenet.pluginmanager.FredPluginFCPMessageHandler.ClientSideFCPMessageHandler;
import freenet.pluginmanager.FredPluginFCPMessageHandler.FCPPluginMessage;
import freenet.pluginmanager.FredPluginFCPMessageHandler.FCPPluginMessage.ClientPermissions;
import freenet.pluginmanager.FredPluginFCPMessageHandler.PrioritizedMessageHandler;
import freenet.pluginmanager.FredPluginFCPMessageHandler.ServerSideFCPMessageHandler;
import freenet.pluginmanager.PluginManager;
import freenet.pluginmanager.PluginNotFoundException;
import freenet.pluginmanager.PluginRespirator;
import freenet.support.Executor;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.PooledExecutor;
import freenet.support.SimpleFieldSet;
import freenet.support.api.Bucket;
import freenet.support.io.NativeThread;

/**
 * <p>An FCP client communicating with a plugin running within fred.</p>
 * 
 * <h1>How to use this properly</h1><br>
 * 
 * You can read the following JavaDoc for a nice overview of how to use this properly from the
 * perspective of your server or client implementation:<br>
 * - {@link PluginRespirator#connectToOtherPlugin(String, ClientSideFCPMessageHandler)}<br>
 * - {@link PluginRespirator#getFCPPluginClientByID(UUID)}<br>
 * - {@link FredPluginFCPMessageHandler}<br>
 * - {@link FredPluginFCPMessageHandler.FCPPluginMessage}<br>
 * - {@link FredPluginFCPMessageHandler.ServerSideFCPMessageHandler}<br>
 * - {@link FredPluginFCPMessageHandler.ClientSideFCPMessageHandler}<br><br>
 * 
 * <h1>Debugging</h1><br>
 * 
 * You can configure the {@link Logger} to log "freenet.node.fcp.FCPPluginClient:DEBUG" to cause
 * logging of all sent and received messages.<br>
 * This is usually done on the Freenet web interface at Configuration / Logs / Detailed priority 
 * thresholds.<br>
 * ATTENTION: The log entries will appear at the time when the messages were queued for sending, not
 * when they were delivered. Delivery usually happens in a separate thread. Thus, the relative order
 * of arrival of messages can be different to the order of their appearance in the log file.<br>
 * If you need to know the order of arrival, add logging to your message handler. Also don't forget
 * that {@link #sendSynchronous(SendDirection, FCPPluginMessage, long)} will not deliver replies
 * to the message handler but only return them instead.<br><br>
 * 
 * <h1>Internals</h1><br>
 * 
 * This section is not interesting to server or client implementations. You might want to read it
 * if you plan to work on the fred-side implementation of FCP plugin messaging.
 * 
 * <h2>Code path of sending messages</h2>
 * <p>There are two possible code paths for client connections, depending upon the location of the
 * client. The server is always running inside the node.<br><br>
 * 
 * NOTICE: These two code paths only apply to asynchronous, non-blocking messages. For blocking,
 * synchronous messages sent by {@link #sendSynchronous(SendDirection, FCPPluginMessage, long)},
 * there is an overview at {@link #synchronousSends}. The overview was left out here because they
 * are built on top of regular messages, so the code paths mentioned here mostly apply.<br><br>
 * 
 * The two possible paths are:<br/>
 * <p>1. The server is running in the node, the client is not - also called networked FCP
 * connections:<br/>
 * - The client connects to the node via network and sends FCP message of type
 *   <a href="https://wiki.freenetproject.org/FCPv2/FCPPluginMessage">FCPPluginMessage</a> (which
 *   will be internally represented by class {@link FCPPluginClientMessage}).<br/>
 * - The {@link FCPServer} creates a {@link FCPConnectionHandler} whose
 *   {@link FCPConnectionInputHandler} receives the FCP message.<br/>
 * - The {@link FCPConnectionInputHandler} uses {@link FCPMessage#create(String, SimpleFieldSet)}
 *   to parse the message and obtain the actual {@link FCPPluginClientMessage}.<br/>
 * - The {@link FCPPluginClientMessage} uses {@link FCPConnectionHandler#getPluginClient(String)} to
 *   obtain the FCPPluginClient which wants to send.<br/>
 * - The {@link FCPPluginClientMessage} uses {@link FCPPluginClient#send(SendDirection,
 *   FCPPluginMessage)} to send the message to the server plugin.<br/>
 * - The FCP server plugin handles the message at
 *   {@link ServerSideFCPMessageHandler#handlePluginFCPMessage(FCPPluginClient, FCPPluginMessage)}.
 *   <br/>
 * - As each FCPPluginClient object exists for the lifetime of a network connection, the FCP server
 *   plugin may store the UUID of the FCPPluginClient and query it via
 *   {@link PluginRespirator#getFCPPluginClientByID(UUID)}. It can use this to send messages to the
 *   client application on its own, that is not triggered by any client messages.<br/>
 * </p>
 * <p>2. The server and the client are running in the same node, also called intra-node FCP
 * connections:</br>
 * - The client plugin uses {@link PluginRespirator#connectToOtherPlugin(String,
 *   FredPluginFCPMessageHandler.ClientSideFCPMessageHandler)} to try to create a connection.<br/>
 * - The {@link PluginRespirator} uses {@link FCPServer#createPluginClientForIntraNodeFCP(String,
 *   FredPluginFCPMessageHandler.ClientSideFCPMessageHandler)} to get a FCPPluginClient.<br/>
 * - The client plugin uses the send functions of the FCPPluginClient. Those are the same as with
 *   networked FCP connections.<br/>
 * - The FCP server plugin handles the message at
 *   {@link ServerSideFCPMessageHandler#handlePluginFCPMessage(FCPPluginClient, FCPPluginMessage)}.
 *   That is the same handler as with networked FCP connections.<br/>
 * - The client plugin keeps a strong reference to the FCPPluginClient in memory as long as it wants
 *   to keep the connection open.<br/>
 * - Same as with networked FCP connections, the FCP server plugin can store the UUID of the
 *   FCPPluginClient and in the future re-obtain the client by
 *   {@link PluginRespirator#getFCPPluginClientByID(UUID)}. It can use this to send messages to the
 *   client application on its own, that is not triggered by any client messages. <br/>
 * - Once the client plugin is done with the connection, it discards the strong reference to the
 *   FCPPluginClient. Because the {@link FCPPluginClientTracker} monitors garbage collection of
 *   {@link FCPPluginClient} objects, getting rid of all strong references to a
 *   {@link FCPPluginClient} is sufficient as a disconnection mechanism.<br/>
 *   Thus, an intra-node client connection is considered as disconnected once the FCPPluginClient is
 *   not strongly referenced by the client plugin anymore. If a server plugin then tries to obtain
 *   the client by its UUID again (via the aforementioned
 *   {@link PluginRespirator#getFCPPluginClientByID(UUID)}, the get will fail. So if the server
 *   plugin stores client UUIDs, it needs no special disconnection mechanism except for periodically
 *   trying to send a message to each client. Once obtaining the client by its UUID fails, or
 *   sending the message fails, the server can opportunistically purge the UUID from its database.
 *   <br/>This mechanism also works for networked FCP.<br>
 * </p></p>
 * 
 * <h2>Object lifecycle</h2>
 * <p>For each {@link #serverPluginName}, a single {@link FCPConnectionHandler} can only have a
 * single FCPPluginClient with the plugin of that name as connection partner. This is enforced by
 * {@link FCPConnectionHandler#getPluginClient(String)}. In other words: One
 * {@link FCPConnectionHandler} can only have one connection to a certain plugin.<br/>
 * The reason for this is the following: Certain plugins might need to store the UUID of a client in
 * their database so they are able to send data to the client if an event of interest to the client
 * happens in the future. Therefore, the UUID of a client must not change during the lifetime of
 * the connection. To ensure a permanent UUID of a client, only a single {@link FCPPluginClient} can
 * exist per server plugin per {@link FCPConnectionHandler}.<br>
 * If you  nevertheless need multiple clients to a plugin, you have to create multiple FCP
 * connections.<br/></p>
 * 
 * <p>
 * In opposite to {@link PersistentRequestClient}, a FCPPluginClient is kept in existence by fred
 * only while the actual client is connected (= in case of networked FCP the parent
 * {@link FCPConnectionHandler} exists; or in case of non-networked FCP while the FCPPluginClient is
 * strong-referenced by the client plugin).<br>
 * There is no such thing as persistence beyond client disconnection.<br/>
 * This was decided to simplify implementation:<br/>
 * - Persistence should be implemented by using the existing persistence framework of
 *   {@link PersistentRequestClient}. That would require extending the class though, and it is a
 *   complex class. The work for extending it was out of scope of the time limit for implementing
 *   this class.<br/>
 * - FCPPluginClient instances need to be created without a network connection for intra-node plugin
 *   connections. If we extended class {@link PersistentRequestClient}, a lot of care would have to
 *   be taken to allow it to exist without a network connection - that would even be more work.<br/>
 * </p>
 * 
 * @author xor (xor@freenetproject.org)
 */
public final class FCPPluginClient {
    
    /** Automatically set to true by {@link Logger} if the log level is set to
     *  {@link LogLevel#DEBUG} for this class.
     *  Used as performance optimization to prevent construction of the log strings if it is not
     *  necessary. */
    private static transient volatile boolean logDEBUG = false;

    /** Automatically set to true by {@link Logger} if the log level is set to
     *  {@link LogLevel#MINOR} for this class.
     *  Used as performance optimization to prevent construction of the log strings if it is not
     *  necessary. */
    private static transient volatile boolean logMINOR = false;
    
    static {
        // Necessary for automatic setting of logDEBUG and logMINOR
        Logger.registerClass(FCPPluginClient.class);
    }


    /**
     * Unique identifier among all FCPPluginClients.
     * @see #getID()
     */
    private final UUID id = UUID.randomUUID();

    /**
     * Executor upon which we run threads of the send functions.<br>
     * Since the send functions can be called very often, it would be inefficient to create a new
     * {@link Thread} for each one. An {@link Executor} prevents this by having a pool of Threads
     * which will be recycled.
     */
    private final Executor executor;

    /**
     * The class name of the plugin to which this FCPPluginClient is connected.
     * @see #getServerPluginName()
     */
    private final String serverPluginName;

    /**
     * The plugin to which this client is connected.
     * 
     * <p>TODO: Optimization / Memory leak fix: Monitor this with a {@link ReferenceQueue} and if it
     * becomes nulled, remove this FCPPluginClient from the map
     * {@link FCPConnectionHandler#pluginClientsByServerPluginName}.<br/>
     * Currently, it seems not necessary:<br/>
     * - It can only become null if the server plugin is unloaded / reloaded. Plugin unloading /
     *   reloading requires user interaction or auto update and shouldn't happen frequently.<br/>
     * - It would only leak one WeakReference per plugin per client network connection. That won't
     *   be much until we have very many network connections. The memory usage of having one thread
     *   per {@link FCPConnectionHandler} to monitor the ReferenceQueue would probably outweight the
     *   savings.<br/>
     * - We already opportunistically clean the table at FCPConnectionHandler: If the client
     *   application which is behind the {@link FCPConnectionHandler} tries to send a message using
     *   a FCPPluginClient whose server WeakReference is null, it is purged from the said table at
     *   FCPConnectionHandler. So memory will not leak as long as the clients keep trying to send
     *   messages to the nulled server plugin - which they probably will do because they did already
     *   in the past.<br/>
     * NOTICE: If you do implement this, make sure to not rewrite the ReferenceQueue polling thread
     *         but instead base it upon {@link FCPPluginClientTracker}. You should probably extract
     *         a generic class WeakValueMap from that one and use to to power both the existing
     *         class and the one which deals with this variable here.
     * </p>
     * @see #isDead() Public interface function to check whether the WeakReference is nulled.
     */
    private final WeakReference<ServerSideFCPMessageHandler> server;

    /**
     * For intra-node plugin connections, this is the connecting client.
     * For networked plugin connections, this is null.
     */
    private final ClientSideFCPMessageHandler client;

    /**
     * For networked plugin connections, this is the connection to which this client belongs.
     * For intra-node connections to plugins, this is null.
     * For each {@link FCPConnectionHandler}, there can only be one FCPPluginClient for each
     * {@link #serverPluginName}.
     */
    private final FCPConnectionHandler clientConnection;
    
    /**
     * @see FCPPluginClient#synchronousSends
     *          An overview of how synchronous sends and especially their threading work internally
     *          is provided at the map which stores them.
     */
    private static final class SynchronousSend {
        /**
         * {@link FCPPluginClient#send(SendDirection, FCPPluginMessage)} shall call
         * {@link Condition#signal()} upon this once the reply message has been stored to
         * {@link #reply} to wake up the sleeping {@link FCPPluginClient#sendSynchronous(
         * SendDirection, FCPPluginMessage, long)} thread which is waiting for the reply to arrive.
         */
        private final Condition completionSignal;
        
        public FCPPluginMessage reply = null;
        
        public SynchronousSend(Condition completionSignal) {
            this.completionSignal = completionSignal;
        }
    }

    /**
     * For each message sent with the <i>blocking</i> send function
     * {@link #sendSynchronous(SendDirection, FCPPluginMessage, long)} this contains a
     * {@link SynchronousSend} object which shall be used to signal the completion of the
     * synchronous send to the blocking sendSynchronous() thread. Signaling the completion tells the
     * blocking sendSynchronous() function that the remote side has sent a reply message to
     * acknowledge that the original message was processed and sendSynchronous() may return now.
     * In addition, the reply is added to the SynchronousSend object so that sendSynchronous() can
     * return it to the caller.<br><br>
     * 
     * The key is the identifier {@link FCPPluginMessage#identifier} of the original message which
     * was sent by sendSynchronous().<br><br>
     * 
     * An entry shall be added by sendSynchronous() when a new synchronous send is started, and then
     * it shall wait for the Condition {@link SynchronousSend#completionSignal} to be signaled.<br>
     * When the reply message is received, the node will always dispatch it via
     * {@link #send(SendDirection, FCPPluginMessage)}. Thus, that function is obliged to check this
     * map for whether there is an entry for each received reply. If it contains a SynchronousSend
     * for the identifier of a given reply, send() shall store the reply message in it, and then
     * call {@link Condition#signal()} upon the SynchronousSend's Condition to cause the blocking
     * sendSynchronous() function to return.<br>
     * The sendSynchronous() shall take the job of removing the entry from this map.<br><br>
     * 
     * Thread safety is to be guaranteed by the {@link #synchronousSendsLock}.<br><br>
     * 
     * When implementing the mechanisms which use this map, please be aware of the fact that bogus
     * remote implementations could:<br>
     * - Not sent a reply message at all, even though they should. This shall be compensated by
     *   sendSynchronous() always specifying a timeout when waiting upon the Conditions.<br>
     * - Send <i>multiple</i> reply messages for the same identifier even though they should only
     *   send one. This probably won't matter though:<br>
     *   * The first arriving reply will complete the matching sendSynchronous() call.<br>
     *   * Any subsequent replies will not find a matching entry in this table, which is the
     *   same situation as if the reply was to a <i>non</i>-synchronous send. Non-synchronous sends
     *   are a normal thing, and thus handling their replies is implemented. It will cause the
     *   reply to be shipped to the message handler interface of the server/client instead of
     *   being returned by sendSynchronous() though, which could confuse it. But in that case
     *   it will probably just log an error message and continue working as normal.
     *   <br><br>
     * 
     * TODO: Optimization: We do not need the order of the map, and thus this could be a HashMap
     * instead of a TreeMap. We do not use a HashMap for scalability: Java HashMaps never shrink,
     * they only grow. As we cannot predict how much parallel synchronous sends server/client
     * implementations will run, we do need a shrinking map. So we use TreeMap. We should use
     * an automatically shrinking HashMap instead once we have one. This is also documented
     * <a href="https://bugs.freenetproject.org/view.php?id=6320">in the bugtracker</a>.
     */
    private final TreeMap<String, SynchronousSend> synchronousSends
        = new TreeMap<String, SynchronousSend>();
    
    /**
     * Shall be used to ensure thread-safety of {@link #synchronousSends}. <br>
     * (Please read its JavaDoc before continuing to read this JavaDoc: It explains the mechanism
     * of synchronous sends, and it is assumed that you understand it in what follows here.)<br><br>
     * 
     * It is a {@link ReadWriteLock} because synchronous sends shall by design be used infrequently,
     * and thus there will be more reads checking for an existing synchronous send than writes
     * to terminate one.
     * (It is a {@link ReentrantReadWriteLock} because that is currently the only implementation of
     * ReadWriteLock, the re-entrancy is probably not needed by the actual code.)
     */
    private final ReadWriteLock synchronousSendsLock = new ReentrantReadWriteLock();


    /**
     * For being used by networked FCP connections:<br/>
     * The server is running within the node, and its message handler is accessible as an
     * implementor of {@link ServerSideFCPMessageHandler}.<br/>
     * The client is not running within the node, it is attached by network with a
     * {@link FCPConnectionHandler}.<br/>
     * 
     * @see #constructForNetworkedFCP(Executor, PluginManager, String, FCPConnectionHandler)
     *          The public interface to this constructor.
     */
    private FCPPluginClient(Executor executor, String serverPluginName,
            ServerSideFCPMessageHandler serverPlugin, FCPConnectionHandler clientConnection) {
        
        assert(executor != null);
        assert(serverPlugin != null);
        assert(serverPluginName != null);
        assert(clientConnection != null);
        
        this.executor = executor;
        this.serverPluginName = serverPluginName;
        this.server = new WeakReference<ServerSideFCPMessageHandler>(serverPlugin);
        this.client = null;
        this.clientConnection = clientConnection;
    }
    
    /**
     * For being used by networked FCP connections:<br/>
     * The server is running within the node, and its message handler will be queried from the
     * {@link PluginManager} via the given String serverPluginName.<br/>
     * The client is not running within the node, it is attached by network with the given
     * {@link FCPConnectionHandler} clientConnection.<br/>
     * 
     * <p>You <b>must</b> register any newly created clients at
     * {@link FCPPluginClientTracker#registerClient(FCPPluginClient)} before handing them out to
     * client application code.</p>
     */
    static FCPPluginClient constructForNetworkedFCP(Executor executor,
            PluginManager serverPluginManager, String serverPluginName,
            FCPConnectionHandler clientConnection)
                throws PluginNotFoundException {
        
        assert(executor != null);
        assert(serverPluginManager != null);
        assert(serverPluginName != null);
        assert(clientConnection != null);
        
        return new FCPPluginClient(executor,
            serverPluginName, serverPluginManager.getPluginFCPServer(serverPluginName),
            clientConnection);
    }


    /**
     * For being used by intra-node connections to a plugin:<br/>
     * Both the server and the client are running within the same node, so objects of their FCP
     * message handling interfaces are available:<br/>
     * The server's message handler is accessible as an implementor of
     * {@link ServerSideFCPMessageHandler}.<br>
     * The client's message handler is accessible as an implementor of
     * {@link ClientSideFCPMessageHandler}.<br>
     * 
     * @see #constructForIntraNodeFCP(Executor, PluginManager, String, ClientSideFCPMessageHandler)
     *          The public interface to this constructor.
     */
    private FCPPluginClient(Executor executor, String serverPluginName,
            ServerSideFCPMessageHandler server, ClientSideFCPMessageHandler client) {
        
        assert(executor != null);
        assert(serverPluginName != null);
        assert(server != null);
        assert(client != null);
        
        this.executor = executor;
        this.serverPluginName = serverPluginName;
        this.server = new WeakReference<ServerSideFCPMessageHandler>(server);
        this.client = client;
        this.clientConnection = null;
    }

    /**
     * For being used by intra-node connections to a plugin:<br/>
     * Both the server and the client are running within the same node, so their FCP interfaces are
     * available:<br/>
     * The server plugin will be queried from given {@link PluginManager} via the given String
     * serverPluginName.<br>
     * The client message handler is available as the passed {@link ClientSideFCPMessageHandler}
     * client.<br>
     * 
     * <p>You <b>must</b> register any newly created clients at
     * {@link FCPPluginClientTracker#registerClient(FCPPluginClient)} before handing them out to
     * client application code.</p>
     */
    static FCPPluginClient constructForIntraNodeFCP(Executor executor,
            PluginManager serverPluginManager, String serverPluginName,
            ClientSideFCPMessageHandler client)
                throws PluginNotFoundException {
        
        assert(executor != null);
        assert(serverPluginManager != null);
        assert(serverPluginName != null);
        assert(client != null);
        
        return new FCPPluginClient(executor,
            serverPluginName, serverPluginManager.getPluginFCPServer(serverPluginName), client);
    }
    
    /**
     * ONLY for being used in unit tests.<br>
     * This is similar to intra-node connections in regular operation: Both the server and client
     * are running in the same VM. You must implement both the server and client side message in
     * the unit test and pass them to this constructor.<br><br>
     * 
     * Notice: Some server plugins might use {@link PluginRespirator#getFCPPluginClientByID(UUID)}
     * to obtain FCPPluginClient objects. So they likely won't work with clients created by this
     * because it doesn't create a PluginRespirator. To get a {@link PluginRespirator} available in
     * unit tests, you might want to use
     * {@link NodeStarter#createTestNode(freenet.node.NodeStarter.TestNodeParameters)} instead 
     * of this constructor:<br>
     * - The test node can be used to load the plugin as a JAR.<br>
     * - As loading a plugin by JAR is the same mode of operation as with a regular node,
     *   there will be a PluginRespirator available to it.<br>
     * - {@link PluginRespirator#connectToOtherPlugin(String, ClientSideFCPMessageHandler)} can then
     *   be used for obtaining a FCPPluginClient instead of this constructor. This also is a
     *   function which is used in regular mode of operation.<br>
     * - The aforementioned {@link PluginRespirator#getFCPPluginClientByID(UUID)} will then work for
     *   FCPPluginClients obtained through the connectToOtherPlugin().
     */
    public static FCPPluginClient constructForUnitTest(ServerSideFCPMessageHandler server,
        ClientSideFCPMessageHandler client) {
        
        assert(server != null);
        assert(client != null);
        return new FCPPluginClient(new PooledExecutor(), server.toString(), server, client);
    }
    
    /**
     * @return A unique identifier among all FCPPluginClients.
     * @see The ID can be used with {@link PluginRespirator#getFCPPluginClientByID(UUID)}.
     */
    public UUID getID() {
        return id;
    }
    
    /**
     * The class name of the plugin to which this FCPPluginClient is connected.
     * @see This is for internal usage by {@link FCPConnectionHandler#getPluginClient(String)}.
     */
    public String getServerPluginName() {
        return serverPluginName;
    }
    
    /**
     * @return <p>True if the server plugin has been unloaded. Once this returns true, this
     *         FCPPluginClient <b>cannot</b> be repaired, even if the server plugin is loaded again.
     *         Then you should discard this client and create a fresh one.</p>
     * 
     *         <p><b>ATTENTION:</b> Future implementations of {@link FCPPluginClient} might allow
     *         the server plugin to reside in a different node, and only be attached by network. To
     *         prepare for that, you <b>must not</b> assume that the connection to the server is
     *         still fine just because this returns false = server is alive. Consider false / server
     *         is alive merely an indication, true / server is dead as the definite truth.<br>
     *         If you need to validate a connection to be alive, send periodic pings. </p>
     */
    public boolean isDead() {
        return server.get() == null;
    }
    
    /**
     * @return The permission level of this client, depending on things such as its IP address.<br>
     *         For intra-node connections, it is {@link ClientPermissions#ACCESS_DIRECT}.<br><br>
     * 
     *         <b>ATTENTION:</b> The return value can change at any point in time, so you should
     *         check this before deploying each FCP message.<br>
     *         This is because the user is free to reconfigure IP-address restrictions on the node's
     *         web interface whenever he wants to.
     */
    private ClientPermissions computePermissions() {
        if(clientConnection != null) { // Networked FCP
            return clientConnection.hasFullAccess() ?
                ClientPermissions.ACCESS_FCP_FULL : ClientPermissions.ACCESS_FCP_RESTRICTED;
        } else { // Intra-node FCP
            assert(client != null);
            return ClientPermissions.ACCESS_DIRECT;
        }
    }

    /**
     * The send functions are fully symmetrical: They work the same way no matter whether client
     * is sending to server or server is sending to client.<br/>
     * Thus, to prevent us from having to duplicate the send functions, this enum specifies in which
     * situation we are.
     */
    public static enum SendDirection {
        ToServer,
        ToClient;
        
        public final SendDirection invert() {
            return (this == ToServer) ? ToClient : ToServer;
        }
    }

    /**
     * Can be used by both server and client implementations to send messages to each other.<br>
     * The messages sent by this function will be delivered to the remote side at either:
     * - the message handler {@link FredPluginFCPMessageHandler#
     *   handlePluginFCPMessage(FCPPluginClient, FCPPluginMessage)}.<br>
     * - or, if existing, a thread waiting for a reply message in
     *   {@link #sendSynchronous(SendDirection, FCPPluginMessage, long)}.<br><br>
     * 
     * This is an <b>asynchronous</b>, non-blocking send function.<br>
     * This has the following differences to the blocking send {@link #sendSynchronous(
     * SendDirection, FCPPluginMessage, long)}:<br>
     * - It may return <b>before</b> the message has been sent.<br>
     *   The message sending happens in another thread so this function can return immediately.<br>
     *   In opposite to that, a synchronousSend() would wait for a reply to arrive, so once it
     *   returns, the message is guaranteed to have been sent.<br>
     * - The reply is delivered to your message handler {@link FredPluginFCPMessageHandler}. It will
     *   not be directly available to the thread which called this function.<br>
     *   A synchronousSend() would return the reply to the caller.<br>
     * - You have no guarantee whatsoever that the message will be delivered.<br>
     *   A synchronousSend() will tell you that a reply was received, which guarantees that the
     *   message was delivered.<br>
     * - The order of arrival of messages is random.<br>
     *   A synchronousSend() only returns after the message was delivered already, so by calling
     *   it multiple times in a row on the same thread, you would enforce the order of the
     *   messages arriving at the remote side.<br><br>
     * 
     * ATTENTION: The consequences of this are:<br>
     * - Even if the function returned without throwing an {@link IOException} you nevertheless must
     *   <b>not</b> assume that the message has been sent.<br>
     * - If the function did throw an {@link IOException}, you <b>must</b> assume that the
     *   connection is dead and the message has not been sent.<br>
     *   You <b>must</b> consider this FCPPluginClient as dead then and create a fresh one.<br>
     * - You can only be sure that a message has been delivered if your message handler receives
     *   a reply message with the same value of
     *   {@link FCPPluginMessage#identifier} as the original message.<br>
     * - You <b>can</b> send many messages in parallel by calling this many times in a row.<br>
     *   But you <b>must not</b> call this too often in a row to prevent excessive threads creation.
     *   <br><br>
     * 
     * ATTENTION: If you plan to use this inside of message handling functions of your
     * implementations of the interfaces
     * {@link FredPluginFCPMessageHandler.ServerSideFCPMessageHandler} or
     * {@link FredPluginFCPMessageHandler.ClientSideFCPMessageHandler}, be sure to read the JavaDoc
     * of the message handling functions first as it puts additional constraints on the usage
     * of the FCPPluginClient they receive.
     * 
     * @param direction
     *            Whether to send the message to the server or the client message handler.<br><br>
     * 
     *            While you <b>can</b> use this to send messages to yourself, be careful not to
     *            cause thread deadlocks with this. The function will call your message
     *            handler function of {@link FredPluginFCPMessageHandler#handlePluginFCPMessage(
     *            FCPPluginClient, FCPPluginMessage)} in <b>a different thread</b>, so it should not
     *            cause deadlocks on its own, but you might produce deadlocks with your own thread
     *            synchronization measures.<br><br>
     * 
     * @param message
     *            You <b>must not</b> send the same message twice: This can break
     *            {@link #sendSynchronous(SendDirection, FCPPluginMessage, long)}.<br>
     *            To ensure this, always construct a fresh FCPPluginMessage object when re-sending
     *            a message. If you use the constructor which allows specifying your own identifier,
     *            always generate a fresh, random identifier.<br>
     *            TODO: Code quality: Add a flag to FCPPluginMessage which marks the message as
     *            sent and use it to log an error if someone tries to send the same message twice.
     *            <br><br>
     * 
     * @throws IOException
     *             If the connection has been closed meanwhile.<br/>
     *             This FCPPluginClient <b>should be</b> considered as dead once this happens, you
     *             should then discard it and obtain a fresh one.
     * 
     *             <p><b>ATTENTION:</b> If this is not thrown, that does NOT mean that the
     *             connection is alive. Messages are sent asynchronously, so it can happen that a
     *             closed connection is not detected before this function returns.<br/>
     *             The only way of knowing that a send succeeded is by receiving a reply message
     *             in your {@link FredPluginFCPMessageHandler}.<br>
     *             If you need to know whether the send succeeded on the same thread which shall
     *             call the send function, you can also use {@link #sendSynchronous(SendDirection,
     *             FCPPluginMessage, long)} which will return the reply right away.</p>
     * @see #sendSynchronous(SendDirection, FCPPluginMessage, long)
     *          You may instead use the blocking sendSynchronous() if your thread needs to know
     *          whether messages arrived, to ensure a certain order of arrival, or to know
     *          the reply to a message.
     */
    public void send(final SendDirection direction, FCPPluginMessage message) throws IOException {
        // We first have to compute the message.permissions field ourselves - we shall ignore what
        // caller said for security.
        ClientPermissions currentPermissions = (direction == SendDirection.ToClient) ?
             null // Server-to-client messages do not have permissions.
             : computePermissions();

        // We set the permissions by creating a fresh FCPPluginMessage object so the caller cannot
        // overwrite what we compute.
        message = FCPPluginMessage.constructRawMessage(currentPermissions, message.identifier,
            message.params, message.data, message.success, message.errorCode, message.errorMessage);

        // Now that the message is completely initialized, we can dump it to the logfile.
        if(logDEBUG) {
            Logger.debug(this, "send(): direction = " + direction + "; " + "message = " + message);
        }
        
        // True if the target server or client message handler is running in this VM.
        // This means that we can call its message handling function in a thread instead of
        // sending a message over the network.
        // Notice that we do not check for server != null because that is not allowed by this class.
        final boolean messageHandlerExistsLocally =
            (direction == SendDirection.ToServer) ||
            (direction == SendDirection.ToClient && client != null);
        
        if(!messageHandlerExistsLocally) {
            dispatchMessageByNetwork(direction, message);
            return;
        }
        
        assert(direction == SendDirection.ToServer ? server != null : client != null)
            : "We already decided that the message handler exists locally. "
            + "We should have only decided so if the handler is not null.";
        
        // Since the message handler is determined to be local at this point, we now must check
        // whether it is a blocking sendSynchronous() thread instead of a regular
        // FredPluginFCPMessageHandler.
        // sendSynchronous() does the following: It sends a message and then blocks its thread
        // waiting for a message replying to it to arrive so it can return it to the caller.
        // If the message we are processing here is a reply, it might be the one which a
        // sendSynchronous() is waiting for.
        if(maybeDispatchMessageLocallyToSendSynchronousThread(direction, message))
            return;
        
        // We now know that the message handler is not attached by network, and that it is not a
        // sendSynchronous() thread. So it must be a FredPluginFCPMessageHandler, and we determine
        // what it is and dispatch the message to it.
        final FredPluginFCPMessageHandler messageHandler
            = (direction == SendDirection.ToServer) ? server.get() : client;

        if(messageHandler == null) {
            // server is a WeakReference which can be nulled if the server plugin was unloaded.
            // client is not a WeakReference, we already checked for it to be non-null.
            // Thus, in this case here, the server plugin has been unloaded so we can have
            // an error message which specifically talks about the *server* plugin.
            throw new IOException("The server plugin has been unloaded.");
        }
        
        dispatchMessageLocallyToMessageHandler(messageHandler, direction, message);
    }
    
    /**
     * Backend for {@link #send(SendDirection, FCPPluginMessage)} to dispatch messages which need
     * to be transported by network.<br><br>
     * 
     * This shall only be called for messages for which it was determined that the message handler
     * is not a plugin running in the local VM.
     */
    private void dispatchMessageByNetwork(final SendDirection direction,
            final FCPPluginMessage message)
                throws IOException {
        
        // The message handler is attached by network.
        // In theory, we could construct a mock FredPluginFCPMessagehandler object for it to
        // pretend it was a local message. But then we wouldn't know the reply message immediately
        // because the messages take time to travel over the network. This wouldn't work with the
        // local message dispatching code as it needs to know the reply immediately so it can send
        // it out. To get the reply, we would have to create a thread which would exist until the
        // reply arrives over the network.
        // So instead, for simplicity and reduced thread count, we just queue the message directly
        // to the network queue here and return.
        
        assert (direction == SendDirection.ToClient)
            : "By design, this class always shall execute in the same VM as the server plugin. "
            + "So for networked messages, we should always be sending to the client.";
        
        assert (clientConnection != null)
            : "Trying to send a message over the network to the client. "
            + "So the network connection to it should not be null.";
        
        if (clientConnection.isClosed())
            throw new IOException("Connection to client closed for " + this);
        
        clientConnection.outputHandler.queue(new FCPPluginServerMessage(serverPluginName, message));
    }

    /**
     * Backend for {@link #send(SendDirection, FCPPluginMessage)} to dispatch messages to a thread
     * waiting in {@link #sendSynchronous(SendDirection, FCPPluginMessage, long)} for the message.
     * <br><br>
     * 
     * This shall only be called for messages for which it was determined that the message handler
     * is a plugin running in the local VM.
     * 
     * @return True if there was a thread waiting for the message and the message was dispatched
     *         to it. You <b>must not</b> dispatch it to the {@link FredPluginFCPMessageHandler}
     *         then.<br><br>
     * 
     *         False if there was no thread waiting for the message. You <b>must<b/> dispatch it
     *         to the {@link FredPluginFCPMessageHandler} then.<br><br>
     * 
     *         (Both these rules are specified in the documentation of sendSynchronous().)
     * @see FCPPluginClient#synchronousSends
     *          An overview of how synchronous sends and especially their threading work internally
     *          is provided at the map which stores them.
     */
    private boolean maybeDispatchMessageLocallyToSendSynchronousThread(final SendDirection direction,
            final FCPPluginMessage message) {
        // Since the message handler is determined to be local at this point, we now must check
        // whether it is a blocking sendSynchronous() thread instead of a regular
        // FredPluginFCPMessageHandler.
        // sendSynchronous() does the following: It sends a message and then blocks its thread
        // waiting for a message replying to it to arrive so it can return it to the caller.
        // If the message we are processing here is a reply, it might be the one which a
        // sendSynchronous() is waiting for.
        // So it is our job to pass the reply to a possibly existing sendSynchronous() thread.
        // We do this through the Map FCPPluginClient.synchronousSends, which is guarded by.
        // FCPPluginClient.synchronousSendsLock. Also see the JavaDoc of the Map for an overview of
        // this mechanism.
        
        if(!message.isReplyMessage()) {
            return false;
        }

        // Since the JavaDoc of sendSynchronous() tells people to use it not very often due to
        // the impact upon thread count, we assume that the percentage of messages which pass
        // through here for which there is an actual sendSynchronous() thread waiting is small.
        // Thus, a ReadWriteLock is used, and we here only take the ReadLock, which can be taken
        // by *multiple* threads at once. We then read the map to check whether there is a
        //  waiter, and if there is, take the write lock to hand the message to it.
        // (The implementation of ReentrantReadWritelock does not allow upgrading a readLock()
        // to a writeLock(), so we must release it in between and re-check afterwards.)

        synchronousSendsLock.readLock().lock();
        try {
            if(!synchronousSends.containsKey(message.identifier)) {
                return false;
            }
        } finally {
            synchronousSendsLock.readLock().unlock();
        }
        
        synchronousSendsLock.writeLock().lock();
        try {
            SynchronousSend synchronousSend = synchronousSends.get(message.identifier);
            if(synchronousSend == null) {
                // The waiting sendSynchronous() has probably returned already because its
                // timeout expired.
                // So by returning false, we ask the caller to deliver the message to the
                // regular message handling interface to make sure that it is not lost.
                return false;
            }

            assert(synchronousSend.reply == null)
                : "One identifier should not be used for multiple messages or replies";

            synchronousSend.reply = message;
            // Wake up the waiting synchronousSend() thread
            synchronousSend.completionSignal.signal();

            return true;
        } finally {
            synchronousSendsLock.writeLock().unlock();
        }
    }

    /**
     * Backend for {@link #send(SendDirection, FCPPluginMessage)} to dispatch messages to a
     * {@link FredPluginFCPMessageHandler}.<br><br>
     * 
     * This shall only be called for messages for which it was determined that the message handler
     * is a plugin running in the local VM.<br><br>
     * 
     * The message will be dispatched in a separate thread so this function can return quickly.
     */
    private void dispatchMessageLocallyToMessageHandler(
            final FredPluginFCPMessageHandler messageHandler, final SendDirection direction,
            final FCPPluginMessage message) {
        
        final Runnable messageDispatcher = new PrioRunnable() {
            @Override
            public void run() {
                FCPPluginMessage reply = null;
                
                try {
                    reply = messageHandler.handlePluginFCPMessage(FCPPluginClient.this, message);
                } catch(RuntimeException e) {
                    // The message handler is a server or client implementation, and thus as third
                    // party code might have bugs. So we need to catch any RuntimeException here.
                    // Notice that this is not normal mode of operation: Instead of throwing,
                    // the JavaDoc requests message handlers to return a reply with success=false.
                    
                    String errorMessage = "FredPluginFCPMessageHandler threw"
                        + " RuntimeException. See JavaDoc of its member interfaces for how signal"
                        + " errors properly."
                        + " Client = " + FCPPluginClient.this + "; SendDirection = " + direction
                        + "; message = " + message;
                    
                    Logger.error(messageHandler, errorMessage, e);
                    
                    if(!message.isReplyMessage()) {
                        // If the original message was not a reply already, we are allowed to send a
                        // reply with success=false to indicate the error to the remote side.
                        // This allows possibly existing, waiting sendSynchronous() calls to fail
                        // quickly instead of having to wait for the timeout because no reply
                        // arrives.
                        reply = FCPPluginMessage.constructReplyMessage(message, null, null, false,
                            "InternalError", errorMessage + "; RuntimeException = " + e.toString());
                    }
                }
                
                if(reply != null) {
                    // Replying to replies is disallowed to prevent infinite bouncing.
                    if(message.isReplyMessage()) {
                        Logger.error(messageHandler, "FredPluginFCPMessageHandler tried to send a"
                            + " reply to a reply. Discarding it. See JavaDoc of its member"
                            + " interfaces for how to do this properly."
                            + " Client = " + FCPPluginClient.this
                            + "; original message SendDirection = " + direction
                            + "; original message = " + message
                            + "; reply = " + reply);
                        
                        reply = null;
                    }
                } else if(reply == null) {
                    if(!message.isReplyMessage()) {
                        // The message handler did not not ship a reply even though it would have
                        // been allowed to because the original message was not a reply.
                        // This shouldn't be done: Not sending a success reply at least will cause
                        // sendSynchronous() threads to keep waiting for the reply until timeout.
                        Logger.warning(
                            messageHandler, "Fred did not receive a reply from the message "
                                          + "handler even though it was allowed to reply. "
                                          + "This would cause sendSynchronous() to timeout! "
                                          + "Original message: " + message);
                    }
                }
                
                // We already tried to set a reply if one is needed. If it is still null now, then
                // we do not have to send one for sure, so we can return.
                if(reply == null) {
                    return;
                }
                
                try {
                    send(direction.invert(), reply);
                } catch (IOException e) {
                    // The remote partner has disconnected, which can happen during normal
                    // operation.
                    // There is nothing we can do to get the IOException out to the caller of the
                    // initial send() of the original message which triggered the reply sending.
                    // - We are in a different thread, the initial send() has returned already.
                    // So we just log it, because it still might indicate problems if we try to
                    // send after disconnection.
                    // We log it marked as from the messageHandler instead of the FCPPluginClient:
                    // The messageHandler will be an object of the server or client plugin,
                    // from a class contained in it. So there is a chance that the developer
                    // has logging enabled for that class, and thus we log it marked as from that.
                    
                    Logger.warning(messageHandler, "Sending reply from FredPluginFCPMessageHandler"
                        + " failed, the connection was closed already."
                        + " Client = " + FCPPluginClient.this
                        + "; original message SendDirection = " + direction
                        + "; original message = " + message
                        + "; reply = " + reply, e);
                }
            }

            @Override
            public int getPriority() {
                NativeThread.PriorityLevel priority = NativeThread.PriorityLevel.NORM_PRIORITY;
                
                if(messageHandler instanceof PrioritizedMessageHandler) {
                    try {
                        priority = ((PrioritizedMessageHandler)messageHandler).getPriority(message);
                    } catch(Throwable t) {
                        Logger.error(messageHandler, "Message handler's getPriority() threw!", t);
                    }
                }
                
                return priority.value;
            }
        };
        
        executor.execute(messageDispatcher, toStringShort());
    }

    /**
     * Can be used by both server and client implementations to send messages in a blocking
     * manner to each other.<br>
     * The messages sent by this function will be delivered to the message handler
     * {@link FredPluginFCPMessageHandler#handlePluginFCPMessage(FCPPluginClient, FCPPluginMessage)}
     * of the remote side.<br><br>
     * 
     * This has the following differences to a regular non-synchronous
     * {@link #send(SendDirection, FCPPluginMessage)}:<br>
     * - It will <b>wait</b> for a reply message of the remote side before returning.<br>
     *   A regular send() would instead queue the message for sending, and then return immediately.
     * - The reply message will be <b>returned to the calling thread</b> instead of being passed to
     *   the message handler {@link FredPluginFCPMessageHandler#handlePluginFCPMessage(
     *   FCPPluginClient, FCPPluginMessage)} in another thread.<br>
     *   NOTICE: It is possible that the reply message <b>is</b> passed to the message handler
     *   upon certain error conditions, for example if the timeout you specify when calling this
     *   function expires before the reply arrives. This is not guaranteed though.<br>
     * - Once this function returns without throwing, it is <b>guaranteed</b> that the message has
     *   arrived at the remote side.<br>
     * - The <b>order</b> of messages can be preserved: If you call sendSynchronous() twice in a
     *   row, the second call cannot execute before the first one has returned, and the returning
     *   of the first call guarantees that the first message was delivered already.<br>
     *   Regular send() calls deploy each message in a thread. This means that the order of delivery
     *   can be different than the order of sending.<br><br>
     * 
     * ATTENTION: This function can cause the current thread to block for a long time, while
     * bypassing the thread limit. Therefore, only use this if the desired operation at the remote
     * side is expected to execute quickly and the thread which sends the message <b>immediately</b>
     * needs one of these after sending it to continue its computations:<br>
     * - An guarantee that the message arrived at the remote side.<br>
     * - An indication of whether the operation requested by the message succeeded.<br>
     * - The reply to the message.<br>
     * - A guaranteed order of arrival of messages at the remote side.<br>
     * A typical example for a place where this is needed is a user interface which has a user
     * click a button and want to see the result of the operation as soon as possible. A detailed
     * example is given at the documentation of the return value below.<br>
     * Notice that even this could be done asynchronously with certain UI frameworks: An event
     * handler could wait asynchronously for the result and fill it in the UI. However, for things
     * such as web interfaces, you might need JavaScript then, so a synchronous call will simplify
     * the code.<br>
     * In addition to only using synchronous calls when absolutely necessary, please make sure to
     * set a timeout parameter which is as small as possible.<br><br>
     * 
     * ATTENTION: While remembering that this function can block for a long time, you have to
     * consider that this class will <b>not</b> call {@link Thread#interrupt()} upon pending calls
     * to this function during shutdown. You <b>must</b> keep track of threads which are executing 
     * this function on your own, and call {@link Thread#interrupt()} upon them at shutdown of your
     * plugin. The interruption will then cause the function to throw {@link InterruptedException}
     * quickly, which your calling threads should obey by exiting to ensure a fast shutdown.<br><br>
     * 
     * ATTENTION: This function can only work properly as long the message which you passed to this
     * function does contain a message identifier which does not collide with one of another
     * message.<br>
     * To ensure this, you <b>must</b> use the constructor {@link FCPPluginMessage#construct(
     * SimpleFieldSet, Bucket)} (or one of its shortcuts) and do not call this function twice upon
     * the same message.<br>
     * If you do not follow this rule and use colliding message identifiers, there might be side
     * effects such as:<br>
     * - This function might return the reply to the colliding message instead of the reply to
     *   your message. Notice that this implicitly means that you cannot be sure anymore that
     *   a message was delivered successfully if this function does not throw.<br>
     * - The reply might be passed to the {@link FredPluginFCPMessageHandler} instead of being
     *   returned from this function.<br>
     * Please notice that both these side effects can also happen if the remote partner erroneously
     * sends multiple replies to the same message identifier.<br>
     * As long as the remote side is implemented using FCPPluginClient as well, and uses it
     * properly, this shouldn't happen though. Thus in general, you should assume that the reply
     * which this function returns <b>is</b> the right one, and your
     * {@link FredPluginFCPMessageHandler} should just drop reply messages which were not expected
     * and log them as at {@link LogLevel#WARNING}. The information here was merely provided to help
     * you with debugging the cause of these events, <b>not</b> to make you change your code
     * to assume that sendSynchronous does not work. For clean code, please write it in a way which
     * assumes that the function works properly.<br><br>
     * 
     * ATTENTION: If you plan to use this inside of message handling functions of your
     * implementations of the interfaces
     * {@link FredPluginFCPMessageHandler.ServerSideFCPMessageHandler} or
     * {@link FredPluginFCPMessageHandler.ClientSideFCPMessageHandler}, be sure to read the JavaDoc
     * of the message handling functions first as it puts additional constraints on the usage
     * of the FCPPluginClient they receive.<br><br>
     * 
     * @param direction
     *            Whether to send the message to the server or the client message handler.<br><br>
     * 
     *            While you <b>can</b> use this to send messages to yourself, be careful not to
     *            cause thread deadlocks with this. The function will call your message
     *            handler function of {@link FredPluginFCPMessageHandler#handlePluginFCPMessage(
     *            FCPPluginClient, FCPPluginMessage)} in <b>a different thread</b>, so it should not
     *            cause deadlocks on its own, but you might produce deadlocks with your own thread
     *            synchronization measures.<br><br>
     * 
     * @param message
     *            <b>Must be</b> constructed using
     *            {@link FCPPluginMessage#construct(SimpleFieldSet, Bucket)}.<br><br>
     * 
     *            Must <b>not</b> be a reply message: This function needs determine when the remote
     *            side has finished processing the message so it knows when to return. That requires
     *            the remote side to send a reply to indicate that the FCP call is finished.
     *            Replies to replies are not allowed though (to prevent infinite bouncing).<br><br>
     * 
     * @param timeoutNanoSeconds
     *            The function will wait for a reply to arrive for this amount of time.<br><br>
     * 
     *            If the timeout expires, an {@link IOException} is thrown.<br>
     *            This FCPPluginClient <b>should be</b> considered as dead once this happens, you
     *            should then discard it and obtain a fresh one.<br><br>
     * 
     *            ATTENTION: The sending of the message is not affected by this timeout, it only
     *            affects how long we wait for a reply. The sending is done in another thread, so
     *            if your message is very large, and takes longer to transfer than the timeout
     *            grants, this function will throw before the message has been sent.<br>
     *            Additionally, the sending of the message is <b>not</b> terminated if the timeout
     *            expires before it was fully transferred. Thus, the message can arrive at the
     *            remote side even if this function has thrown, and you might receive an off-thread
     *            reply to the message in the {@link FredPluginFCPMessageHandler}.<br><br>
     *            
     *            Notice: For convenience, use class {@link TimeUnit} to easily convert seconds,
     *            milliseconds, etc. to nanoseconds.<br><br>
     * 
     * @return The reply {@link FCPPluginMessage} which the remote partner sent to your message.
     *         <br><br>
     * 
     *         <b>ATTENTION</b>: Even if this function did not throw, the reply might indicate an
     *         error with the field {link FCPPluginMessage#success}: This can happen if the message
     *         was delivered but the remote message handler indicated that the FCP operation you
     *         initiated failed.<br>
     *         The fields {@link FCPPluginMessage#errorCode} and
     *         {@link FCPPluginMessage#errorMessage} might indicate the type of the error.<br><br>
     * 
     *         This can be used to decide to retry certain operations. A practical example
     *         would be a user trying to create an account at an FCP server application:<br>
     *         - Your UI would use this function to try to create the account by FCP.<br>
     *         - The user might type an invalid character in the username.<br>
     *         - The server could then indicate failure of creating the account by sending a reply
     *           with success == false.<br>
     *         - Your UI could detect the problem by success == false at the reply and an errorCode
     *           of "InvalidUsername". The errorCode can be used to decide to highlight the username
     *           field with a red color.<br>
     *         - The UI then could prompt the user to chose a valid username by displaying the
     *           errorMessage which the server provides to ship a translated, human readable
     *           explanation of what is wrong with the username.<br>
     * @throws IOException
     *             If the given timeout expired before a reply was received <b>or</b> if the
     *             connection has been closed before even sending the message.<br>
     *             This FCPPluginClient <b>should be</b> considered as dead once this happens, you
     *             should then discard it and obtain a fresh one.
     * @throws InterruptedException
     *             If another thread called {@link Thread#interrupt()} upon the thread which you
     *             used to execute this function.<br>
     *             This is a shutdown mechanism: You can use it to abort a call to this function
     *             which is waiting for the timeout to expire.<br><br>
     * @see FCPPluginClient#synchronousSends
     *          An overview of how synchronous sends and especially their threading work internally
     *          is provided at the map which stores them.
     * @see #send(SendDirection, FCPPluginMessage)
     *          The non-blocking, asynchronous send() should be used instead of this whenever
     *          possible.
     */
    public FCPPluginMessage sendSynchronous(SendDirection direction, FCPPluginMessage message,
            long timeoutNanoSeconds)
                throws IOException, InterruptedException {
        
        if(message.isReplyMessage()) {
            throw new IllegalArgumentException("sendSynchronous() cannot send reply messages: " +
                "If it did send a reply message, it would not get another reply back. " +
                "But a reply is needed for sendSynchronous() to determine when to return.");
        }
        
        assert(timeoutNanoSeconds > 0) : "Timeout should not be negative";
        
        assert(timeoutNanoSeconds <= TimeUnit.MINUTES.toNanos(1))
            : "Please use sane timeouts to prevent thread congestion";
        
        
        synchronousSendsLock.writeLock().lock();
        try {
            final Condition completionSignal = synchronousSendsLock.writeLock().newCondition();
            final SynchronousSend synchronousSend = new SynchronousSend(completionSignal);
            
            // An assert() instead of a throwing is fine:
            // - The constructor of FCPPluginMessage which we tell the user to use in the JavaDoc
            //   does generate a random identifier, so collisions will only happen if the user
            //   ignores the JavaDoc or changes the constructor.
            // - If the assert is not true, then the following put() will replace the old
            //   SynchronousSend, so its Condition will never get signaled, and its
            //   thread waiting in sendSynchronous() will timeout safely. It IS possible that this
            //   thread will then get a reply which does not belong to it. But the wrong reply will
            //   only affect the caller, the FCPPluginClient will keep working fine, especially
            //   no threads will become stalled for ever. As the caller is at fault for the issue,
            //   it is fine if he breaks his own stuff :) The JavaDoc also documents this.
            
            assert(!synchronousSends.containsKey(message.identifier))
                : "FCPPluginMessage.identifier should be unique";
            
            synchronousSends.put(message.identifier, synchronousSend);
            
            if(logMINOR) {
                Logger.minor(this, "sendSynchronous(): Started for identifier " + message.identifier
                                 + "; synchronousSends table size: " + synchronousSends.size());
            }
            
            send(direction, message);
            
            // Message is sent, now we wait for the reply message to be put into the SynchronousSend
            // object by the thread which receives the reply message.
            // - That usually happens at FCPPluginClient.send().
            // Once it has put it into the SynchronousSend object, it will call signal() upon
            // our Condition completionSignal.
            // This will make the following awaitNanos() wake up and return true, which causes this
            // function to be able to return the reply.
            do {
                // The compleditionSignal is a Condition which was created from the
                // synchronousSendsLock.writeLock(), so it will be released by the awaitNanos()
                // while it is blocking, and re-acquired when it returns.
                timeoutNanoSeconds = completionSignal.awaitNanos(timeoutNanoSeconds);
                if(timeoutNanoSeconds <= 0) {
                    // Include the FCPPluginMessage in the Exception so the developer can determine
                    // whether it is an issue of the remote side taking a long time to execute
                    // for certain messages.
                    throw new IOException("The synchronous call timed out for " + this + "; "
                                        + "direction = " + direction + "; "
                                        + "message = " + message);
                }

                // The thread which sets synchronousSend.reply to be non-null calls
                // completionSignal.signal() only after synchronousSend.reply has been set.
                // So the naive assumption would be that at this point of code,
                // synchronousSend.reply would be non-null because awaitNanos() should only return
                // true after signal() was called.
                // However, Condition.awaitNanos() can wake up "spuriously", i.e. wake up without
                // actually having been signal()ed. See the JavaDoc of Condition.
                // So after awaitNanos() has returned true to indicate that it might have been
                // signaled we still need to check whether the semantic condition which would
                // trigger signaling is *really* met, which we do with this if:
                if(synchronousSend.reply != null) {
                    assert(synchronousSend.reply.identifier.equals(message.identifier));
                    
                    return synchronousSend.reply;
                }

                // The spurious wakeup described at the above if() has happened, so we loop.
            } while(true);
        } finally {
            // We MUST always remove the SynchronousSend object which we added to the map,
            // otherwise it will leak memory eternally.
            synchronousSends.remove(message.identifier);
            
            if(logMINOR) {
                Logger.minor(this, "sendSynchronous(): Done for identifier " + message.identifier
                                 + "; synchronousSends table size: " + synchronousSends.size());
            }
            
            synchronousSendsLock.writeLock().unlock();
        }
    }

    @Override
    public String toString() {
        return "FCPPluginClient (ID: " + id + "; server plugin: " + serverPluginName + "; client: "
                   + client + "; clientConnection: " + clientConnection +  ")";
    }

    public String toStringShort() {
        return "FCPPluginClient for " + serverPluginName;
    }

    /**
     * ATTENTION: For unit test use only.
     * 
     * @return The size of the backend table {@link #synchronousSends} of
     *         {@link #sendSynchronous(SendDirection, FCPPluginMessage, long)}
     */
    int getSendSynchronousCount() {
        synchronousSendsLock.readLock().lock();
        try {
            return synchronousSends.size();
        } finally {
            synchronousSendsLock.readLock().unlock();
        }
    }
}