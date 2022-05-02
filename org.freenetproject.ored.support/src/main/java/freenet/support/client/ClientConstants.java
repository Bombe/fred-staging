package freenet.support.client;

// TODO: Modularity: Remove these constants from class HighLevelSimpleClientImpl
public final class ClientConstants {
    // For scaling purposes, 128 data 128 check blocks i.e. one check block per data block.
    public static final int SPLITFILE_SCALING_BLOCKS_PER_SEGMENT = 128;
    /* The number of data blocks in a segment depends on how many segments there are.
     * FECCodec.standardOnionCheckBlocks will automatically reduce check blocks to compensate for more than half data blocks. */
    public static final int SPLITFILE_BLOCKS_PER_SEGMENT = 136;
    public static final int SPLITFILE_CHECK_BLOCKS_PER_SEGMENT = 128;
    public static final int EXTRA_INSERTS_SINGLE_BLOCK = 2;
    public static final int EXTRA_INSERTS_SPLITFILE_HEADER = 2;
}
