package freenet.nodeapp;

import freenet.client.async.ClientRequestScheduler;
import freenet.client.request.RequestClient;
import freenet.client.request.SimpleSendableInsert;
import freenet.keys.CHKBlock;
import freenet.keys.KeyBlock;
import freenet.keys.SSKBlock;

public class NodeSimpleSendableInsert extends SimpleSendableInsert {
    public NodeSimpleSendableInsert(RequestClient nonPersistentClientBulk, ClientRequestScheduler chkPutSchedulerBulk, ClientRequestScheduler sskPutSchedulerBulk, KeyBlock block, short prioClass) {
        super(nonPersistentClientBulk, chkPutSchedulerBulk, sskPutSchedulerBulk, block, prioClass);
    }

    public NodeSimpleSendableInsert(KeyBlock block, short prioClass, RequestClient client, ClientRequestScheduler scheduler) {
        super(block, prioClass, client, scheduler);
    }

    public NodeSimpleSendableInsert(NodeClientCore core, KeyBlock block, short prioClass) {
        super(block, prioClass, core.node.nonPersistentClientBulk, getScheduler(core, block));
    }

    private static ClientRequestScheduler getScheduler(NodeClientCore core, KeyBlock block) {
        ClientRequestScheduler scheduler;

        if(block instanceof CHKBlock)
            scheduler = core.requestStarters.chkPutSchedulerBulk;
        else if(block instanceof SSKBlock)
            scheduler = core.requestStarters.sskPutSchedulerBulk;
        else
            throw new IllegalArgumentException("Don't know what to do with "+block);
        if(!scheduler.isInsertScheduler())
            throw new IllegalStateException("Scheduler "+scheduler+" is not an insert scheduler!");

        return scheduler;
    }
}
