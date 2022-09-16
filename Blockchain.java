import java.io.*;
import java.util.*;
import java.text.*;
import java.nio.file.*;
import java.net.*;
import java.util.concurrent.*;
import java.security.*;
import java.security.spec.KeySpec;
import com.google.gson.*;

import java.io.*;
import java.util.*;
import java.nio.file.*;
import java.net.*;
import java.util.concurrent.*;
import java.security.*;
import java.security.spec.KeySpec;
import com.google.gson.*;


// from bc.java
// setup Port number for each process
class Ports {
    public static int MulitcastServerPortBase = 4600; // p1 = 4601, p2= 4602

    public static int KeyServerPortBase = 4710; // p1 = 4711, p2 = 4712
    public static int UnverifiedBlockServerPortBase = 4820; // p1 = 4820, p2 = 4820
    public static int BlockchainServerPortBase = 4930; // p1 = 4931, p2 = 4932

    public static int MulitcastServerPort;

    public static int KeyServerPort;
    public static int UnverifiedBlockServerPort;
    public static int BlockchainServerPort;

    public void setPorts() {
        MulitcastServerPort = MulitcastServerPortBase + bc.PID;

        KeyServerPort = KeyServerPortBase + bc.PID;
        UnverifiedBlockServerPort = UnverifiedBlockServerPortBase + bc.PID;
        BlockchainServerPort = BlockchainServerPortBase + bc.PID;

    }
}



// Working code
// from Work.b
class WorkB {

	public static String ByteArrayToString(byte[] ba) {
		StringBuilder hex = new StringBuilder(ba.length * 2);
		for (int i = 0; i < ba.length; i++) {
			hex.append(String.format("%02X", ba[i]));
		}
		return hex.toString();
	}

	public static String randomAlphaNumeric(int count) {
		StringBuilder builder = new StringBuilder();
		while (count-- != 0) {
			int character = (int) (Math.random() * ALPHA_NUMERIC_STRING.length());
			builder.append(ALPHA_NUMERIC_STRING.charAt(character));
		}
		return builder.toString();
	}

	private static final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";


	// Try 20 times, return null if cannot find answer
	public static String getAnswerSeed(String data) {
		try {
			for (int i = 1; i < 20; i++) {
				String randString = randomAlphaNumeric(8);
				String concatString = data + randString;
				MessageDigest MD = MessageDigest.getInstance("SHA-256");
				byte[] bytesHash = MD.digest(concatString.getBytes("UTF-8"));
				String stringOut = ByteArrayToString(bytesHash);
				int workNumber = Integer.parseInt(stringOut.substring(0, 4), 16);
				if (workNumber < 20000) {
					String puzzleAnswer = randString;
					return puzzleAnswer;
				}
			}
			return null;
		} catch (Exception x) {
			x.printStackTrace();
			return null;
		}
	}
}




class BlockRecord implements Serializable {
    /* Examples of block fields. You should pick, and justify, your own set: */
    UUID uuid; // Just to show how JSON marshals this binary data.

    String BlockID;
    // String TimeStamp;
    int PID; // PID that create a block
    Date TimeStamp;
    String VerificationProcessID;

    String PreviousHash; // We'll copy from previous block

    String Fname;
    String Lname;
    String SSNum;
    String DOB;
    String Diag;
    String Treat;
    String Rx;

    String RandomSeed; // Our guess. Ultimately our winning guess.
    String WinningHash;



    BlockRecord() {
        uuid = UUID.randomUUID();    
    }

    public static Comparator<BlockRecord> BlockTSComparator = new Comparator<BlockRecord>() {
        @Override
        public int compare(BlockRecord b1, BlockRecord b2) {
            // String s1 = b1.getTimeStampString();
            // String s2 = b2.getTimeStampString();
            Date s1 = b1.getTimeStamp();
            Date s2 = b1.getTimeStamp();

            if (s1 == s2) {
                return 0;
            }
            if (s1 == null) {
                return -1;
            }
            if (s2 == null) {
                return 1;
            }
            return s1.compareTo(s2);
        }
    };

    /* Examples of accessors for the BlockRecord fields: */
    public String getBlockID() {
        return BlockID;
    }

    public void setBlockID(String BID) {
        this.BlockID = BID;
    }


    public int getPID() {
        return this.PID;
    }
    
    public void setPID(int PID) {
        this.PID = PID;
    }

    public Date getTimeStamp() {
        return this.TimeStamp;
    }

    public String getTimeStampString() {
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss_SSS");
        return formatter.format(TimeStamp) + PID;
        // return TimeStamp.toString() + "." + PID;
    }

    public void setTimeStamp(Date TS) {
        this.TimeStamp = TS;
    }

    public String getVerificationProcessID() {
        return VerificationProcessID;
    }

    public void setVerificationProcessID(String VID) {
        this.VerificationProcessID = VID;
    }

    public String getPreviousHash() {
        return this.PreviousHash;
    }

    public void setPreviousHash(String PH) {
        this.PreviousHash = PH;
    }

    public UUID getUUID() {
        return uuid;
    } 

    public void setUUID(UUID ud) {
        this.uuid = ud;
    }

    public String getLname() {
        return Lname;
    }

    public void setLname(String LN) {
        this.Lname = LN;
    }

    public String getFname() {
        return Fname;
    }

    public void setFname(String FN) {
        this.Fname = FN;
    }

    public String getSSNum() {
        return SSNum;
    }

    public void setSSNum(String SS) {
        this.SSNum = SS;
    }

    public String getDOB() {
        return DOB;
    }

    public void setDOB(String RS) {
        this.DOB = RS;
    }

    public String getDiag() {
        return Diag;
    }

    public void setDiag(String D) {
        this.Diag = D;
    }

    public String getTreat() {
        return Treat;
    }

    public void setTreat(String Tr) {
        this.Treat = Tr;
    }

    public String getRx() {
        return Rx;
    }

    public void setRx(String Rx) {
        this.Rx = Rx;
    }

    public String getRandomSeed() {
        return RandomSeed;
    }

    public void setRandomSeed(String RS) {
        this.RandomSeed = RS;
    }

    public String getWinningHash() {
        return WinningHash;
    }

    public void setWinningHash(String WH) {
        this.WinningHash = WH;
    }

    public String getData() {
        return getFname() + getLname() + getDOB() + getDiag() + getTreat() + getRx();
    }

    // json marshalling
    public String getPrettyJson() {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        return gson.toJson(this);
    }

    public String getJson() {
        Gson gson = new GsonBuilder().create();
        return gson.toJson(this);
    }

    public static BlockRecord fromJson(String json) {
        Gson gson = new Gson();
        return gson.fromJson(json, BlockRecord.class);
    }


    // from BlockInputG.java
    // for parse line from BlockInputX.txt

    private static final int iFNAME = 0;
    private static final int iLNAME = 1;
    private static final int iDOB = 2;
    private static final int iSSNUM = 3;
    private static final int iDIAG = 4;
    private static final int iTREAT = 5;
    private static final int iRX = 6;

    public static BlockRecord parseLine(String line) {
        BlockRecord BR = new BlockRecord();
        String[] tokens = new String[10];
        String InputLineStr = line;
        String suuid;

        try {
            Thread.sleep(0);
        } catch (InterruptedException e) {
        }

        // setup TimeStamp
        BR.setPID(bc.PID);
        BR.setTimeStamp(new Date()); 

        suuid = new String(UUID.randomUUID().toString());

        BR.setBlockID(suuid);

        tokens = InputLineStr.split(" +"); 
        BR.setFname(tokens[iFNAME]);
        BR.setLname(tokens[iLNAME]);
        BR.setSSNum(tokens[iSSNUM]);
        BR.setDOB(tokens[iDOB]);
        BR.setDiag(tokens[iDIAG]);
        BR.setTreat(tokens[iTREAT]);
        BR.setRx(tokens[iRX]);


        return BR;
    }

    // calculate Block's hash
    public String getSHA256Hash() throws NoSuchAlgorithmException {
        String blockData = getPreviousHash() + getRandomSeed() + getData();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(blockData.getBytes());
        byte[] byteData = md.digest();

        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < byteData.length; i++) {
            sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
        }
        return sb.toString();
    }


    // for first block in BlockchainLedger
    static BlockRecord genesisBlock;
    public static BlockRecord getGenesisBlock() {
        if (genesisBlock == null) {
            genesisBlock = new BlockRecord();
            genesisBlock.uuid = UUID.randomUUID();
            genesisBlock.BlockID = UUID.randomUUID().toString();
            genesisBlock.setTimeStamp(new Date());
        }
        return genesisBlock;
    }
}




// from bc.java
class PublicKeyWorker extends Thread {
    Socket sock; 

    PublicKeyWorker(Socket s) {
        sock = s;
    } 

    public void run() {
        try {

            ObjectInputStream oin = new ObjectInputStream(sock.getInputStream());

            PublicKey publicKey = (PublicKey) oin.readObject();
            bc.appendLogFile("Got key: " + publicKey.toString() + "\n");

            // Check for duplicate key befor add.
            if (!bc.publicKeyList.contains(publicKey)) {
                bc.publicKeyList.add(publicKey);
            }

            sock.close();
        } catch (Exception x) {
            x.printStackTrace();
        }
    }
}




// from bc.java
class PublicKeyServer implements Runnable {

    public void run() {

        System.out.println("keys total: " + bc.publicKeyList.size());
        int q_len = 6;
        Socket sock;
        bc.appendLogFile("Starting Key Server input thread using " + Integer.toString(Ports.KeyServerPort));

        try {
            ServerSocket servsock = new ServerSocket(Ports.KeyServerPort, q_len);

            while (true) {
                sock = servsock.accept();

                // set flag to check if all processes' serveris running.
                if (!bc.AllProcessRunning) {
                    bc.AllProcessRunning  = true;
                }
                new PublicKeyWorker(sock).start();
            }
        } catch (IOException ioe) {
            System.out.println(ioe);
        }

    }
}





// from bc.java
class UnverifiedBlockServer implements Runnable {
    BlockingQueue<BlockRecord> queue;

    UnverifiedBlockServer(BlockingQueue<BlockRecord> queue) {
        this.queue = queue;
    }
    public static Comparator<BlockRecord> BlockTSComparator = new Comparator<BlockRecord>() {
        @Override
        public int compare(BlockRecord b1, BlockRecord b2) {
            String s1 = b1.getTimeStampString();
            String s2 = b2.getTimeStampString();
            if (s1 == s2) {
                return 0;
            }
            if (s1 == null) {
                return -1;
            }
            if (s2 == null) {
                return 1;
            }
            return s1.compareTo(s2);
        }
    };


    class UnverifiedBlockWorker extends Thread { 
        Socket sock; 

        UnverifiedBlockWorker(Socket s) {
            sock = s;
        }

        BlockRecord BR;

        public void run() {

            try {
                ObjectInputStream oin = new ObjectInputStream(sock.getInputStream());
                BR = (BlockRecord) oin.readObject();

                if (BR != null) {
                    bc.appendLogFile("Received UVB: " + BR.getTimeStampString() + " " + BR.getData());
                    queue.put(BR);
                    bc.TotalQueueSize = queue.size();
                }

                sock.close();
            } catch (Exception x) {
                x.printStackTrace();
            }
        }
    }

    // UnverifiedBlockServer.run()
    public void run() {
        int q_len = 6;
        Socket sock;

        bc.appendLogFile("Starting the Unverified Block Server input thread using "
                + Integer.toString(Ports.UnverifiedBlockServerPort));

        try {
            ServerSocket UVBServer = new ServerSocket(Ports.UnverifiedBlockServerPort, q_len);
            while (true) {
                sock = UVBServer.accept(); 

                bc.appendLogFile("Got connection to UVB Server.");

                new UnverifiedBlockWorker(sock).start(); 
            }
        } catch (IOException ioe) {
            System.out.println(ioe);
        }
    }

}




// from bc.java
// Work is done here.
class UnverifiedBlockConsumer implements Runnable {
    PriorityBlockingQueue<BlockRecord> queue;
    int PID;

    UnverifiedBlockConsumer(PriorityBlockingQueue<BlockRecord> queue) {
        this.queue = queue;
    }

    public void run() {
        BlockRecord tempRec;

        bc.appendLogFile("Starting the Unverified Block Priority Queue Consumer thread. (UnverifiedBlockConsumer)");
        try {
            while (true) {

                // perform Work to get RandomSeed
                tempRec = queue.take();

                bc.appendLogFile("Working..." + tempRec.getData());

                String answerSeed = WorkB.getAnswerSeed(tempRec.getData());

                // if Work produce valid answer, set the Block's previousHash to
                // BlockchainLedger's last Block's hash
                if (answerSeed != null) {
                    BlockRecord prevBlockRecord = bc.BlockchainLedger.getLast();
                    tempRec.PreviousHash = prevBlockRecord.getSHA256Hash();

                    bc.appendLogFile("\tWork done, answer = " + answerSeed);

                    // Send Verified Block to all processes.
                    bc.BlockRecordSend(tempRec);
                    bc.appendLogFile("Send Verified BlockRecord " + tempRec.getData());
                }

                // Thread.sleep(300);
            }
        } catch (Exception e) {
            System.out.println(e);
        }
    }
}




class BlockchainWorker extends Thread {
    Socket sock;

    BlockchainWorker(Socket s) {
        sock = s;
    }

    public void run() {
        try {
            ObjectInputStream oin = new ObjectInputStream(sock.getInputStream());

            try {
                // Got Verfied Block
                BlockRecord BR = (BlockRecord) oin.readObject();
                bc.appendLogFile("Get Verified Block " + BR.getData());
                if (BR != null) {

                    // check for duplicate before add Verified Block to Ledger
                    if (!bc.verifiedList.contains(BR.uuid)) {
                        bc.BlockchainLedger.add(BR);
                        bc.verifiedList.add(BR.uuid); 
                        bc.appendLogFile("\tAdd Verified Block to BlockchainLedger " + BR.getData());
                    } else {
                        bc.appendLogFile("\tDuplicated: do not add " + BR.getData());
                    }
                }

                // When Blockchain update, save BlockChainLedger.json on process 0
                if (bc.PID == 0) {
                    bc.Save_BlockchainLedger_json();
                }

                // show Blockchain status
                System.out.println("queue left = " + bc.ourPriorityQueue.size() + " / " + bc.TotalQueueSize);
                System.out.println("Blockchain size = " + bc.BlockchainLedger.size());

            } catch (Exception x) {
                sock.close();
            }

            sock.close();
        } catch (

        IOException x) {
            x.printStackTrace();
        }
    }
}



class BlockchainServer implements Runnable {

    public void run() {
        int q_len = 6; /* Number of requests for OpSys to queue */
        Socket sock;

        bc.appendLogFile(
                "Starting the Blockchain server input thread using " + Integer.toString(Ports.BlockchainServerPort));

        try {
            ServerSocket servsock = new ServerSocket(Ports.BlockchainServerPort, q_len);

            while (true) {
                sock = servsock.accept();
                new BlockchainWorker(sock).start();
            }

        } catch (IOException ioe) {
            System.out.println(ioe);
        }
    }
}



class bc {

    // use to keep PublicKey and PrivateKay
    static KeyPair keyPair;

    // publicKey from all processes
    static List<PublicKey> publicKeyList = new ArrayList<>();

    // flag to check if all server is running, set after process 2 is finished
    // launching
    static boolean AllProcessRunning = false;

    // static boolean workSolved = false;

    static String serverName = "localhost";

    static int numProcesses = 3;
    static int PID = 0;

    static LinkedList<BlockRecord> recordList = new LinkedList<>(); // Unsend BlockRecord from BLockInputX.txt

    // Verfied Block list (Blockchain)
    static LinkedList<BlockRecord> BlockchainLedger = new LinkedList<>();

    // Before add Verified Block, check this list to prevent duplicate.
    static List<UUID> verifiedList = new ArrayList<>();

    // PriorityBlockingQueue (and Comparator) from bc.java
    public static Comparator<BlockRecord> BlockTSComparator = new Comparator<BlockRecord>() {
        @Override
        public int compare(BlockRecord b1, BlockRecord b2) {
            // String s1 = b1.getTimeStampString();
            // String s2 = b2.getTimeStampString();
            Date s1 = b1.getTimeStamp();
            Date s2 = b2.getTimeStamp();
            if (s1 == s2) {
                return 0;
            }
            if (s1 == null) {
                return -1;
            }
            if (s2 == null) {
                return 1;
            }
            return s1.compareTo(s2);
        }
    };

    public static PriorityBlockingQueue<BlockRecord> ourPriorityQueue = new PriorityBlockingQueue<>(100,
            BlockTSComparator);

    public static int TotalQueueSize;

    // crypto method from BlockJ.java
    // verifySig(), generateKeyPair(), signData()
    public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initVerify(key);
        signer.update(data);
        return (signer.verify(sig));
    }

    public static KeyPair generateKeyPair(long seed) throws Exception {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
        rng.setSeed(seed);
        keyGenerator.initialize(1024, rng);
        return (keyGenerator.generateKeyPair());
    }

    public static byte[] signData(byte[] data, PrivateKey key) throws Exception {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(key);
        signer.update(data);
        return (signer.sign());
    }

    // read and parse BlockRecord from BlockInputX.txt
    // and add to recordList
    public static void AddBlockRecordfromBlockInputFile(String BlockInputFilename) {

        BlockRecord BR;

        Path filepath = Paths.get(BlockInputFilename);
        if (Files.exists(filepath)) {
            try {
                List<String> lines = Files.readAllLines(filepath);
                for (String line : lines) {
                    BR = BlockRecord.parseLine(line);
                    if (BR != null) {
                        BR.setPID(PID);
                        BR.setTimeStamp(new Date());
                        recordList.add(BR);
                        // Thread.sleep(1001);
                    }
                }

                bc.appendLogFile("Read " + bc.recordList.size() + " BlockRecord(s) from file");

            } catch (Exception x) {
                x.printStackTrace();
            }

        }
    }

    // methods for Multicast PublicKey, from bc.java
    public static void KeySend() {

        if (keyPair == null) {
            Random rand = new Random();
            try {
                keyPair = generateKeyPair(rand.nextLong());
                PublicKey publicKey = keyPair.getPublic();
            } catch (Exception x) {
                x.printStackTrace();
            }
        }

        Socket sock;
        ObjectOutputStream toServerOOS;
        try {
            for (int i = 0; i < numProcesses; i++) {
                int portToSend = Ports.KeyServerPortBase + i;
                sock = new Socket(serverName, portToSend);
                toServerOOS = new ObjectOutputStream(sock.getOutputStream());
                PublicKey publicKey = keyPair.getPublic();
                toServerOOS.writeObject(publicKey);

                bc.appendLogFile("Send PublicKey to " + portToSend);

                toServerOOS.flush();
                sock.close();
            }
        } catch (Exception x) {
            // x.printStackTrace();
            System.err.println("error: KeySend()");
        }
    }

    // methods for Multicast Unverified Block (from recordList), from bc.java
    public static void UnverifiedSend() {
        Socket sock;
        Random r = new Random();
        try {
            Iterator<BlockRecord> iterator = recordList.iterator();

            ObjectOutputStream toServerOOS;

            for (int i = 0; i < numProcesses; i++) {
                int port = Ports.UnverifiedBlockServerPortBase + i;

                bc.appendLogFile("Sending UVBs to process " + port + "...");

                iterator = recordList.iterator();
                while (iterator.hasNext()) {
                    sock = new Socket(serverName, Ports.UnverifiedBlockServerPortBase + i);

                    toServerOOS = new ObjectOutputStream(sock.getOutputStream());

                    Thread.sleep((r.nextInt(9) * 100)); // Sleep up to a second to randominze when sent.
                    BlockRecord BR = iterator.next();
                    toServerOOS.writeObject(BR);
                    toServerOOS.flush();

                    bc.appendLogFile("send block: " + BR.getData());

                    sock.close();
                }
            }
            Thread.sleep((r.nextInt(9) * 100)); // Sleep up to a second to randominze when sent.
        } catch (Exception x) {
            x.printStackTrace();
        }
    }

    // Multicast BlockRecord to all processes, similar to UnverifiedSend()
    // send Verified BlockRecord to BlockchainServer
    public static void BlockRecordSend(BlockRecord BR) {
        Socket sock;
        Random r = new Random();
        ObjectOutputStream toServerOOS;
        try {

            for (int i = 0; i < numProcesses; i++) {
                int port = Ports.BlockchainServerPortBase + i;
                bc.appendLogFile("Sending New Verified BlockRecord " + port + "...");
                sock = new Socket(serverName, Ports.BlockchainServerPortBase + i);

                toServerOOS = new ObjectOutputStream(sock.getOutputStream());
                Thread.sleep((r.nextInt(9) * 100));
                toServerOOS.writeObject(BR);
                toServerOOS.flush();

                sock.close();
            }
        } catch (Exception x) {
            x.printStackTrace();
        }
    }

    // Multicast Blockchain(Ledger) to all processes, similar to UnverifiedSend()
    public static void BlockchainSend() {
        Socket sock;
        Random r = new Random();
        ObjectOutputStream toServerOOS;
        try {

            for (int i = 0; i < numProcesses; i++) {
                int port = Ports.BlockchainServerPortBase + i;
                bc.appendLogFile("Sending Updated BlockchainLedger " + port + "...");
                sock = new Socket(serverName, Ports.BlockchainServerPortBase + i);

                toServerOOS = new ObjectOutputStream(sock.getOutputStream());
                Thread.sleep((r.nextInt(9) * 100));
                toServerOOS.writeObject(BlockchainLedger);
                toServerOOS.flush();

                sock.close();
            }
        } catch (Exception x) {
            x.printStackTrace();
        }
    }

    // for write log file: BlockchainLog.txt
    // also print to each process console
    public static void appendLogFile(String msg) {
        try {
            msg = "process " + bc.PID + ": " + msg + "\n";
            Files.write(Paths.get("BlockchainLog.txt"), msg.getBytes(), StandardOpenOption.APPEND);
            System.out.println(msg);
        } catch (Exception x) {
            x.printStackTrace();
        }
    }

    // Marshell Blockchain to file BlockchainLedger.json
    public static void Save_BlockchainLedger_json() {
        try {
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            String json = gson.toJson(bc.BlockchainLedger);
            Files.write(Paths.get("BlockchainLedger.json"), json.getBytes());
            Files.write(Paths.get("BlockchainLedgerSample.json"), json.getBytes()); // for submit

            bc.appendLogFile("write BlockchainLedger.json");

        } catch (Exception x) {
            x.printStackTrace();
        }
    }

    // from bc.java
    // Start all server, but wait for all processes' server fully running
    // Before start UnverifiedBlockConsumer
    public void run(String args[]) {

        System.out.println("Running now\n");
        
        PID = (args.length < 1) ? 0 : Integer.parseInt(args[0]);

        System.out.println("Sornthorn's Blockchain. Use Control-C to stop the process.\n");
        System.out.println("Using processID " + PID + "\n");
        bc.appendLogFile("start process " + PID);

        new Ports().setPorts();

        // add Genesis Block as the first one
        bc.BlockchainLedger.add(BlockRecord.getGenesisBlock()); 

        try {
            Files.write(Paths.get("BlockchainLog.txt"), "".getBytes()); // clear BlockchainLog.txt contents

            // start all server
            new Thread(new BlockchainServer()).start();
            Thread.sleep(100);
            new Thread(new UnverifiedBlockServer(ourPriorityQueue)).start();
            Thread.sleep(100);
            new Thread(new PublicKeyServer()).start();

            Thread.sleep(1000);

            if (bc.PID == 2) {
                // since process 2 is the last one,
                // set flag bc.AllProcessRunning bc.AllProcessRunning = true;
                // Multicast PublicKey & UVB from process 2.

                // When other process receive the PublicKey from process 2,
                // it will set the flac bc.AllProcessRunning in their own process
                bc.KeySend();
                bc.UnverifiedSend();
            }

            // wait for all server to run before continue
            while (!bc.AllProcessRunning) {
                Thread.sleep(500);
            }
            bc.appendLogFile("-- all processes's server is running --");

            // Multicast PublicKey & UVB from process 0, 1
            if (bc.PID < 2) {
                bc.KeySend();
                bc.UnverifiedSend();
            }

            // wait and start UnverifiedBlockConsumer
            Thread.sleep(1500);
            new Thread(new UnverifiedBlockConsumer(ourPriorityQueue)).start();
            bc.appendLogFile("start UnverifiedBlockConsumer");
        } catch (Exception e) {
        }
    }

}


/* 
   first version
   1. marshall as java object (instead of json)
   2. use fake work

   second version
   3. add comment
   4. usee real work
   5. produce BlockChainLog.txt

*/

public class Blockchain {
    
    public static void main(String[] args) {

        if (args.length != 1) {
            System.err.println("Wrong Argument Length: " + args.length);
            System.exit(0);
        }

        bc s = new bc();

        /* 
            Set process PID base on argument.
            Also read (and parse) BlockRecord from BlockInputX.txt, put into recordList (Unverified Block list)
        */
        switch (args[0]) {
            case "0":
                bc.PID = 0;
                bc.AddBlockRecordfromBlockInputFile("BlockInput0.txt");
                break;
            case "1":
                bc.PID = 1;
                bc.AddBlockRecordfromBlockInputFile("BlockInput1.txt");
                break;
            case "2":
                bc.PID = 2;
                bc.AddBlockRecordfromBlockInputFile("BlockInput2.txt");
                break;
            default:
                System.err.println("Argument error");
                System.exit(0);
        }
        
        // main program is in class bc
        s.run(args);
    }
}

