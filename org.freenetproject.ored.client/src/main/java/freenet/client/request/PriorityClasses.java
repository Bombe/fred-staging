package freenet.client.request;

// TODO: Modularity: Remove these fields from RequestStarter
public class PriorityClasses {
    /*
     * Priority classes
     */
    /** Anything more important than FProxy */
    public static final short MAXIMUM_PRIORITY_CLASS = 0;
    /** FProxy etc */
    public static final short INTERACTIVE_PRIORITY_CLASS = 1;
    /** FProxy splitfile fetches */
    public static final short IMMEDIATE_SPLITFILE_PRIORITY_CLASS = 2;
    /** USK updates etc */
    public static final short UPDATE_PRIORITY_CLASS = 3;
    /** Bulk splitfile fetches */
    public static final short BULK_SPLITFILE_PRIORITY_CLASS = 4;
    /** Prefetch */
    public static final short PREFETCH_PRIORITY_CLASS = 5;
    /** Anything less important than prefetch (redundant??) */
    public static final short PAUSED_PRIORITY_CLASS = 6;

    public static final short NUMBER_OF_PRIORITY_CLASSES = PAUSED_PRIORITY_CLASS - MAXIMUM_PRIORITY_CLASS + 1; // include 0 and max !!

    public static final short MINIMUM_FETCHABLE_PRIORITY_CLASS = PREFETCH_PRIORITY_CLASS;

    public static boolean isValidPriorityClass(int prio) {
        return !((prio < MAXIMUM_PRIORITY_CLASS) || (prio > PAUSED_PRIORITY_CLASS));
    }
}
