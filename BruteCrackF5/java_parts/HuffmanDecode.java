/* Version 0.1 of F5 Steganography Software by Andreas Westfeld 1999 */
/***********************************************************/
/*      JPEG Decoder                                       */
/*      Sean Breslin                                       */
/*      EE590 Directed Research                            */
/*      Dr. Ortega                                         */
/*      Fall 1997                                          */
/*                                                         */
/*      HuffmanDecode.class:                               */
/*            This object performs entopy decoding on      */
/*            a JPEG image file. This object instanciates  */
/*            HuffTable.class which extracts the Huffman   */
/*            Tables from the file header information.     */
/*                                                         */
/*            Methods:                                     */
/*                 HuffDecode(), returns array of 8x8      */
/*                               blocks of image data      */
/*                 getX(), returns horizontal image size   */
/*                 getY(), returns vertical image size     */
/*                 getPrec(), returns sample precision     */
/*                 getComp(), returns number of components */
/*		   rawDecode(), returns quantized	   */
/*				coefficients		   */
/*                                                         */
/********************** 11/4/97 ****************************/
//
// changes by Andreas Westfeld
// <mailto:westfeld@inf.tu-dresden.de>
package java_parts;
//
// Mar 15 1999
// constructor changed to byte array parameter
// added method rawDecode
// 
import java.io.*;
import java.net.*;
import java.awt.*;
import java.util.*;

public class HuffmanDecode {
    private final static int APP0=(int)0xE0; 
    private final static int APP1=(int)0xE1; 
    private final static int APP2=(int)0xE2; 
    private final static int APP3=(int)0xE3; 
    private final static int APP4=(int)0xE4; 
    private final static int APP5=(int)0xE5; 
    private final static int APP6=(int)0xE6; 
    private final static int APP7=(int)0xE7; 
    private final static int APP8=(int)0xE8; 
    private final static int APP9=(int)0xE9; 
    private final static int APP10=(int)0xEA; 
    private final static int APP11=(int)0xEB; 
    private final static int APP12=(int)0xEC; 
    private final static int APP13=(int)0xED; 
    private final static int APP14=(int)0xEE; 
    private final static int APP15=(int)0xEF; 
    private final static int DRI=(int)0xDD; 
    private final static int DNL=(int)0xDC; 
    private final static int EOI=(int)0xD9; 

    // Instance variables
    // Declare header variables
    private int lengthF, dataPrecision, imageWidth, imageHeight, numComponents;
    private int[] compID, horzSampFac, vertSampFac, qTableNum;// SOF0 parameters
    private int lengthS, numComponentsS;            // SOS  parameters
    private int Ss, Se, Ah, Al;                     // SOS  parameters (unused)
    private int[] compSelect, huffDC, huffAC;       // SOS  parameters
    private int lengthHT, typeHT, numHT;            // DHT  parameters
    private int lengthQT, precisionQT, numQT;       // DQT  parameters
    private int Ld, Nl;                             // DNL  parameters
    private int Lr, Ri;                             // DRI  parameters
    
    // other variables
    private int B, CNT, DIFF, PRED, size;
    private int K, SSSS, RS, R, J, CODE;
    private int i, cnt, a, b, huffTable;
    private int[][][] Cr, Cb;
    private int[][] HUFFVAL = new int[4][];
    private int[][] VALPTR  = new int[4][];
    private int[][] MINCODE = new int[4][];
    private int[][] MAXCODE = new int[4][];
    private int[] ZZ        = new int[64];
    private int[][] QNT     = new int[4][64];
    private int lengthRI;
    private static byte[][] deZZ = {
        {0,0},
        {0,1},{1,0},
        {2,0},{1,1},{0,2},
        {0,3},{1,2},{2,1},{3,0},
        {4,0},{3,1},{2,2},{1,3},{0,4},
        {0,5},{1,4},{2,3},{3,2},{4,1},{5,0},
        {6,0},{5,1},{4,2},{3,3},{2,4},{1,5},{0,6},
        {0,7},{1,6},{2,5},{3,4},{4,3},{5,2},{6,1},{7,0},
        {7,1},{6,2},{5,3},{4,4},{3,5},{2,6},{1,7},
        {2,7},{3,6},{4,5},{5,4},{6,3},{7,2},
        {7,3},{6,4},{5,5},{4,6},{3,7},
        {4,7},{5,6},{6,5},{7,4},
        {7,5},{6,6},{5,7},
        {6,7},{7,6},
        {7,7}
    };

// added for decode()    
    private static byte[] deZigZag = {
       0,  1,  5,  6, 14, 15, 27, 28,
       2,  4,  7, 13, 16, 26, 29, 42,
       3,  8, 12, 17, 25, 30, 41, 43,
       9, 11, 18, 24, 31, 40, 44, 53,
      10, 19, 23, 32, 39, 45, 52, 54,
      20, 22, 33, 38, 46, 51, 55, 60,
      21, 34, 37, 47, 50, 56, 59, 61,
      35, 36, 48, 49, 57, 58, 62, 63
    };
    
    // Constructor Method
    public HuffmanDecode(byte[] data) throws IOException {
	size = (short) data.length;
	dis = new DataInputStream(new ByteArrayInputStream(data));
	// Parse out markers and header info
        boolean cont = true;
        while(cont) {
            if(255 == getByte()) {
		switch(getByte()) {
		    case 192:   sof0(); break;
                    case 194:   throw new IOException("Progressive scan JPEGs not supported by decoder");
		    case 196:   defineHuffmanTable(); break;
		    case 219:   defineQuantTable(); break;
		    case 217:   cont = false; break;
		    case 218:   cont = false; break;
		    case APP0:
		    case APP1:
		    case APP2:
		    case APP3:
		    case APP4:
		    case APP5:
		    case APP6:
		    case APP7:
		    case APP8:
		    case APP9:
		    case APP10:
		    case APP11:
		    case APP12:
		    case APP13:
		    case APP14:
		    case APP15: skipVariable(); break;
		    case DRI:   defineRestartInterval(); break;
		}
	    }
	}
    }
    
    private void sof0(){
        // Read in start of frame header data
        lengthF       = getInt();
        dataPrecision = getByte();
        imageHeight   = getInt();
        imageWidth    = getInt();
        numComponents = getByte();
	
        compID      = new int[numComponents];
        horzSampFac = new int[numComponents]; //Horizontal Sampling Factor
        vertSampFac = new int[numComponents]; //Vertical Sampling Factor
        qTableNum   = new int[numComponents];
	
        // Read in quatization table identifiers
        for(i=0; i<numComponents; i++) {
            compID[i] = getByte();
            horzSampFac[i] = getByte();    //LSBs = vert, MSBs = horz
            vertSampFac[i] = horzSampFac[i] &  0x0f;
                horzSampFac[i] >>= 4;
            qTableNum[i] = getByte();
        }
    }
    
    private void defineHuffmanTable(){
        // Read in Huffman tables
        // System.out.println("Read in Huffman tables");
        lengthHT = getInt();
	while (lengthHT>0) {
	    typeHT = getByte(); //LSBs = Number of, BIT4 = type, BIT5-7 Unused 
	    numHT = typeHT & 0x0f;
            typeHT >>= 4;
            // 0 = DC Table, 1 = AC Table
// System.out.println("______Huffman Length="+lengthH);
	    if(numHT==0){
		if(typeHT==0){                
		    htDC0 = new HuffTable(dis, lengthHT);
		    lengthHT-=htDC0.getLen();
		    HUFFVAL[0] = htDC0.getHUFFVAL();
		    VALPTR[0]  = htDC0.getVALPTR();
		    MAXCODE[0] = htDC0.getMAXCODE();
// System.out.println("MAXCODE[0]="+MAXCODE[0]);
		    MINCODE[0] = htDC0.getMINCODE();
		    htDC0 = null;
		    System.gc();
		}
		else {
		    htAC0 = new HuffTable(dis, lengthHT);
		    lengthHT-=htAC0.getLen();
		    HUFFVAL[1] = htAC0.getHUFFVAL();
		    VALPTR[1]  = htAC0.getVALPTR();
		    MAXCODE[1] = htAC0.getMAXCODE();
// System.out.println("MAXCODE[1]="+MAXCODE[1]);
		    MINCODE[1] = htAC0.getMINCODE();
		    htAC0 = null;
		    System.gc();
		}
	    }
	    else {
		if(typeHT == 0) {
		    htDC1 = new HuffTable(dis, lengthHT);
		    lengthHT-=htDC1.getLen();
		    HUFFVAL[2] = htDC1.getHUFFVAL();
		    VALPTR[2]  = htDC1.getVALPTR();
		    MAXCODE[2] = htDC1.getMAXCODE();
// System.out.println("MAXCODE[2]="+MAXCODE[2]);
		    MINCODE[2] = htDC1.getMINCODE();
		    htDC1 = null;
		    System.gc();
		}
		else {
		    htAC1 = new HuffTable(dis, lengthHT);
		    lengthHT-=htAC1.getLen();
		    HUFFVAL[3] = htAC1.getHUFFVAL();
		    VALPTR[3]  = htAC1.getVALPTR();
		    MAXCODE[3] = htAC1.getMAXCODE();
// System.out.println("MAXCODE[3]="+MAXCODE[3]);
		    MINCODE[3] = htAC1.getMINCODE();
		    htAC1 = null;
		    System.gc();
		}
	    }
	}
    }
    
    private void defineQuantTable(){
	
        // Read in quatization tables
        lengthQT     = getInt();
        precisionQT = getByte(); //LSBs = number of QT, HSBs = precision of QT
        
        numQT = precisionQT & 0x0f;
        precisionQT >>= 4;
	
        switch(numQT) {
            case 0: for(i=0;i<64;i++)
		    QNT[0][i] = getByte();
	    break;
	    
            case 1: for(i=0;i<64;i++)
		    QNT[1][i] = getByte();
	    break;
	    
            case 2: for(i=0;i<64;i++)
		    QNT[2][i] = getByte();
	    break;
	    
            case 3: for(i=0;i<64;i++)
		    QNT[3][i] = getByte();
	    break;
        }
    }

    private void defineRestartInterval() {
	getInt();lengthRI=getInt();
    }

    private void skipVariable(){
	try {
	        dis.skipBytes(getInt()-2);
	    } catch (IOException e) {
	        e.printStackTrace();
	    }
    }
    
    private int available(){
	try {
	    return dis.available();
	} catch (IOException e) {
	    e.printStackTrace();
	}
	return 0;
    }
    
    private void Decode_AC_coefficients() {
        K = 1;
	
        // Zero out array ZZ[]
        for(i=1;i<64;i++)
            ZZ[i] = 0;
	
        while(true) {
//System.out.println(hftbl);
            RS = DECODE();
            SSSS = RS % 16;
            R = RS >> 4;
            if(SSSS == 0) {
                if(R == 15) {
                    K += 16;
                    continue;
                } else
                    return;
            } else {
                K = K + R;
                Decode_ZZ(K);
                if(K == 63)
                    return;
                else
                    K++;
            }
        }
    }
    
    private void Decode_ZZ(int k) {
        // Decoding a nonzero AC coefficient
        ZZ[k] = RECEIVE(SSSS);
        ZZ[k] = EXTEND(ZZ[k], SSSS);
    }
    
    private int NextBit() {
        // Get one bit from entropy coded data stream
        int b2, lns, BIT;
	
        if(CNT == 0) {
            CNT=8;
            B = getByte();
	    if(255 == B)  // Process markers or strip byte padding
                b2 = getByte();
        }
        BIT =  B & 0X80;    // get MSBit of B
	BIT >>= 7;          // move MSB to LSB
        CNT--;              // Decrement counter
        B <<= 1;            // Shift left one bit
        return BIT;
    }
    
    private int DECODE() {
        int I, CD, VALUE;
	
        CD = NextBit();
        I = 1;
	
        while(true) {
//System.out.println(hftbl+" "+I);
            if(CD > MAXCODE[huffTable][I]) {
                CD = (CD << 1) + NextBit();
                I++;
            } else {
                break;
            }
        }
        J = VALPTR[huffTable][I];
        J = J + CD - MINCODE[huffTable][I];
        VALUE = HUFFVAL[huffTable][J];
        return VALUE;
    }
    
    private int RECEIVE(int SSS) {
        int V = 0, I = 0;
	
        while(true) {
            if(I == SSS)
                return V;
            I++;
            V = (V << 1) + NextBit();
        }
    }
    
    private int EXTEND(int V, int T) {
        int Vt;
	
        Vt = (0x01 << (T-1));
        if(V < Vt) {
	    Vt = (-1 << T) + 1;
            V += Vt;
        }
        return V;
    }
    
    public int getByte() {
        int b=0;
        // Read Byte from DataInputStream
        try {
            b = dis.readUnsignedByte();
        } catch (IOException e) {
	    e.printStackTrace();
	}
        return b;
    }
    
    public int getInt() {
        int b=0;
        // Read Integer from DataInputStream
        try {
            b = dis.readUnsignedByte();
            b <<= 8;
            int tmp = dis.readUnsignedByte();
            b ^= tmp;
        } catch (IOException e) {
	    e.printStackTrace();
	}
        return b;
    }
    
    private void closeStream() {
        // Close input stream
        try {
            dis.close(); // close io stream to file
	} catch (IOException e) {}
    }
    
    // Public get methods
    public int getX() { return imageWidth; }
    public int getY() { return imageHeight; }
    public int getPrec() { return dataPrecision; }
    public int getComp() { return numComponents; }
    // Calculate the Number of blocks encoded
    public int getBlockCount() {
	switch (numComponents) {
	case 1:
	    return ((imageWidth+7)/8)*((imageHeight+7)/8);
	case 3:
	    return 6*((imageWidth+15)/16)*((imageHeight+15)/16);
	default:
	    System.out.println("Neither 1 nor 3");
	}
	return 0;
    }
    public void setCr(int[][][] chrome) { Cr = chrome; }
    public void setCb(int[][][] chrome) { Cb = chrome; }
    
    
    // Return image data
    public void HuffDecode(int[][][] buffer) {
        int x, y, tmp, sz = imageWidth * imageHeight, scan=0;
        int[][] Block   = new int[8][8];        
        int compSelect, huffAC, huffDC, blocks;
        long t;
        double time;
	
        // Read in Scan Header information
        lengthS = getInt();
        numComponentsS = getByte();
        compSelect = getByte();
        huffDC = getByte();
            huffAC = huffDC & 0x0f;
        huffDC >>= 4;
	
        //Unused
        Ss = getByte();
        Se = getByte();
        Ah = getByte();
         Al = Ah & 0x0f;
         Ah >>= 4;
        
        // Calculate the Number of blocks encoded
        //blocks = X * Y / 64;
	blocks = getBlockCount()/6;
        
        // decode image data and return image data in array        
        for(cnt=0; cnt<blocks; cnt++) {
	    // Get DC coefficient
	    if(huffDC == 0)
		huffTable = 0;
	    else
		huffTable = 2;
	    tmp = DECODE();
	    DIFF = RECEIVE(tmp);
	    ZZ[0] = PRED + EXTEND(DIFF, tmp);
	    PRED = ZZ[0];
	    
	    // Get AC coefficients
	    if(huffAC == 0)
		huffTable = 1;
	    else
		huffTable = 3;
	    Decode_AC_coefficients();
	    
	    // dezigzag and dequantize block
	    for(i=0;i<64;i++)
		Block[deZZ[i][0]][deZZ[i][1]] = ZZ[i] * QNT[0][i];
	    
	    // store blocks in buffer
	    for(x=0;x<8;x++)
		for(y=0;y<8;y++)
		buffer[cnt][x][y]=Block[x][y];
        }
        closeStream();
    }
    
    // Return quantized coefficients
    public void rawDecode(int[][][] buffer) {
        int x, y, tmp;
        int[][] Block   = new int[8][8];        
        int compSelect, huffAC, huffDC, blocks;
        long t;
        double time;
	
        // Read in Scan Header information
        lengthS = getInt();
        numComponentsS = getByte();
        compSelect = getByte();
        huffDC = getByte();
         huffAC = huffDC & 0x0f;
         huffDC >>= 4;
	
        //unused
        Ss = getByte();
        Se = getByte();
        Ah = getByte();
         Al = Ah & 0x0f;
         Ah >>= 4;
        
        // Calculate the Number of blocks encoded
        blocks = getBlockCount()/6;
        
        // decode image data and return image data in array        
        for(cnt=0; cnt<blocks; cnt++) {
	        // Get DC coefficient
	        if(huffDC == 0)
		        huffTable = 0;
	        else
		        huffTable = 2;
	        tmp = DECODE();
	        DIFF = RECEIVE(tmp);
	        ZZ[0] = PRED + EXTEND(DIFF, tmp);
	        PRED = ZZ[0];
	    
	        // Get AC coefficients
	        if(huffAC == 0)
		        huffTable = 1;
	        else
		        huffTable = 3;
	        Decode_AC_coefficients();
	    
	        // dezigzag
	        for(i=0; i<64; i++)
		        Block[deZZ[i][0]][deZZ[i][1]] = ZZ[i];
	    
	        // store blocks in buffer
	        System.out.print(cnt+" ");
	        for(x=0; x<8; x++) {
		        for(y=0;y<8;y++) {
		            buffer[cnt][x][y]=Block[x][y];
		        }
	        }
        }
        closeStream();
    }
    
    // Return image data for RGB images
    public void RGBdecode(int[][][] Lum) {
        int x, y, a, b, line, col, tmp, sz = imageWidth * imageHeight;
        int blocks, MCU, scan=0;
        int[][] Block   = new int[8][8];
        int[] compSelect, huffAC, huffDC;
        int[] PRED = {0, 0, 0};
        long t;
        double time;
	
        // Read in Scan Header information
        lengthS = getInt();
        numComponentsS = getByte();
        compSelect = new int[numComponentsS];
        huffDC = new int[numComponentsS];
        huffAC = new int[numComponentsS];
	
        // get table information
        for(i=0; i<numComponentsS; i++) {
            compSelect[i] = getByte();
            huffDC[i] = getByte();
            huffAC[i] = huffDC[i] & 0x0f;
             huffDC[i] >>= 4;
        }
	
        //unused
        Ss = getByte();
        Se = getByte();
        Ah = getByte();
         Al = Ah & 0x0f;
         Ah >>= 4;
	
        // Calculate the Number of blocks encoded
        //blocks = X * Y / 64;
	blocks = getBlockCount()/6;
        col = 2;        
	
        // decode image data and return image data in array
        for(a=0; a<32; a++)
            for(b=0; b<32; b++) {
            // Get component 1 of MCU
            for(cnt=0; cnt<4; cnt++){
                // Get DC coefficient
                huffTable = 0;
                tmp = DECODE();
                DIFF = RECEIVE(tmp);
                ZZ[0] = PRED[0] + EXTEND(DIFF, tmp);
                PRED[0] = ZZ[0];
		
                // Get AC coefficients
                huffTable = 1;
                Decode_AC_coefficients();
		
                // dezigzag and dequantize block
                for(i=0; i<64; i++)
                    Block[deZZ[i][0]][deZZ[i][1]] = ZZ[i] * QNT[0][i];
		
                if(cnt<2) line = 0;
                else line = 62;
		
                // store blocks in buffer
                for(x=0;x<8;x++)
                    for(y=0;y<8;y++)
		    Lum[b*2+cnt+line+a*128][x][y]=Block[x][y];
            }
	    
            // getComponent 2 and 3 of image
            for(cnt=0; cnt<2; cnt++) {
                // Get DC coefficient
                huffTable = 2;
                tmp = DECODE();
                DIFF = RECEIVE(tmp);
                ZZ[0] = PRED[cnt+1] + EXTEND(DIFF, tmp);
                PRED[cnt+1] = ZZ[0];
		
                // Get AC coefficients
                huffTable = 3;
                Decode_AC_coefficients();
		
                // dezigzag and dequantize block
                for(i=0;i<64;i++)
                    Block[deZZ[i][0]][deZZ[i][1]] = ZZ[i] * QNT[1][i];
		
                // store blocks in buffer
                if(cnt == 0) {
		    for(x=0; x<8; x++)
			for(y=0;y<8;y++)
			Cb[a*32+b][x][y]=Block[x][y];
                }
                else {
		    for(x=0; x<8; x++)
			for(y=0;y<8;y++)
			Cr[a*32+b][x][y]=Block[x][y];
                }
            }
        }
        closeStream();
    }

    // Return image data 
    public int [] decode() {
        int x, y, a, b, line,/* col,*/ tmp;//, sz = X * Y;
        int blocks, MCU;//, scan=0;
        int[] compID, huffAC, huffDC;
        int[] PRED = new int[numComponents];
	    for(int nComponent=0; nComponent<numComponents; nComponent++)
	        PRED[nComponent]=0;
        long t;
        double time;
	    CNT=0;
        // Read in Scan Header information
        lengthS = getInt();
        numComponentsS = getByte();
	//System.out.println("SOS - Components: "+Integer.toString(Ns));
        compID = new int[numComponentsS];
        huffDC = new int[numComponentsS];
        huffAC = new int[numComponentsS];
	
        // get table information
        for(i=0;i<numComponentsS;i++) {
            compID[i] = getByte();
            huffDC[i] = getByte();
             huffAC[i] = huffDC[i] & 0x0f;
             huffDC[i] >>= 4;
//System.out.println("DC-Table: "+Integer.toString(Td[lp])+"AC-Table: "+Integer.toString(Ta[lp])); 
	}
	
        // Progressive scan parameters (not used here)
        Ss = getByte();
        Se = getByte();
        Ah = getByte();
         Al = Ah & 0x0f;
         Ah >>= 4;
	
        // Calculate the Number of blocks encoded
// warum doppelt so viel?
	int buff[]=new int[2*8*8*getBlockCount()];
	int pos=0;
	int MCUCount=0;

//System.out.println("BlockCount="+getBlockCount());
	boolean bDoIt=true;
	while(bDoIt) {
	    // Get component 1 of MCU
            for(int nComponent=0; nComponent<numComponents; nComponent++) {
		    for(cnt=0; cnt<horzSampFac[nComponent]*
                                           vertSampFac[nComponent]; cnt++) {
		        // Get DC coefficient
		        huffTable = huffDC[nComponent]*2;
		        tmp = DECODE();
		        DIFF = RECEIVE(tmp);
		        ZZ[0] = PRED[0] + EXTEND(DIFF, tmp);
		        PRED[nComponent] = ZZ[0];
		    
		        // Get AC coefficients
		        huffTable = huffAC[nComponent]*2+1;
		        Decode_AC_coefficients();
		    
                        for(i=0;i<64;i++) {
                            //System.out.println("pos="+pos);
//Zickzack???               // buff[pos++]=ZZ[deZigZag[lp]];
                            buff[pos++]=ZZ[i];
                        }
                    }
	    }
	    
	    MCUCount++;
	    if(MCUCount==lengthRI) {
		MCUCount=0;
		CNT=0;
		for(int nComponent=0; nComponent<numComponents; nComponent++)
		    PRED[nComponent]=0;
		//System.out.println("MCUCount");
		getByte();
		//System.out.println(Integer.toHexString(getByte()));
		int tmpB=getByte();
		//System.out.println(Integer.toHexString(tmpB));
		if(tmpB==EOI)
		    break;
		//System.out.println("MCUCount-Ende");
	    }
	    if(available()<=2) {
		//System.out.println("expecting end of image");
		if (available()==2) {
		    getByte();
		    if (getByte() != EOI)
			System.out.println("file does not end with EOI");
		} else {
		    if (available()>0)
			System.out.println(Integer.toHexString(getByte()));
		    System.out.println("file does not end with EOI");
		}
		break;
	    }
        }
	int[] tmpBuff=new int[pos];
	System.arraycopy(buff,0,tmpBuff,0,pos);
	return tmpBuff;
    }
    
    //{{ Control Objects
    HuffTable htDC0, htDC1;
    HuffTable htAC0, htAC1;
    DataInputStream dis;
    TextArea ta;
    Date dt;
    //}}
}
