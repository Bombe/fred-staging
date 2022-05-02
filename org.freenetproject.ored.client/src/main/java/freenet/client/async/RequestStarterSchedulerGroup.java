package freenet.client.async;

public interface RequestStarterSchedulerGroup {
    ClientRequestScheduler getChkFetchSchedulerBulk();

    ClientRequestScheduler getChkPutSchedulerBulk();

    ClientRequestScheduler getSskFetchSchedulerBulk();

    ClientRequestScheduler getSskPutSchedulerBulk();

    ClientRequestScheduler getChkFetchSchedulerRT();

    ClientRequestScheduler getChkPutSchedulerRT();

    ClientRequestScheduler getSskFetchSchedulerRT();

    ClientRequestScheduler getSskPutSchedulerRT();

    void setGlobalSalt(byte[] salt);
}
