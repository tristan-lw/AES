using System.Data;
using System.Diagnostics.Metrics;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading.Tasks.Dataflow;

namespace AES
{
    internal class Config
    {
        private string line;
        private string endS;
        private string keyBytesS;
        private string keyStringS;
        private string plaintextS;
        private string hexPrefix;
        private string configFile;
        private int index;
        private int startIndex;
        private int endIndex;
        internal string[] outputFiles { get; }

        internal string Path { get; }
        internal byte[] Key { get; set; }
        internal string Plaintext { get; set; }
        internal Config()
        {
            keyBytesS = "keyBytes:";
            keyStringS = "keyString:";
            plaintextS = "plaintext:";
            endS = "# End #";
            hexPrefix = "0x";
            Key = new byte[16];
            Path = "C:\\Users\\Tristan\\source\\repos\\REAL AES PROJECT\\AES\\Files\\";
            configFile = "C:\\Users\\Tristan\\source\\repos\\REAL AES PROJECT\\AES\\config.txt";
            outputFiles = new string[] {
                "initial.txt",
                "round1.txt", "round2.txt", "round3.txt", "round4.txt", "round5.txt",
                "round6.txt", "round7.txt", "round8.txt", "round9.txt", "round10.txt",
                "final.txt"
            };
            foreach (string file in outputFiles) {
                if (File.Exists(Path + file))
                {
                    File.Delete(Path + file);
                    File.WriteAllText(Path + file, string.Empty);
                }
                else
                {
                    File.WriteAllText(Path + file, string.Empty);
                }
            }
            try
            {
                StreamReader sr = new StreamReader(configFile);
                while (line != endS)
                {
                    line = sr.ReadLine();
                    if (line.StartsWith(keyBytesS))
                    {
                        StoreKeyBytes();
                    }
                    else if (line.StartsWith(plaintextS))
                    {
                        StorePlaintext();
                    } else if (line.StartsWith(keyStringS))
                    {
                        StoreKeyString();
                    }
                }
                sr.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine("Exception: " + e.Message);
            }
            File.AppendAllText(
                Path + outputFiles[0],
                "# Key #\n" + Convert.ToHexString(Key) + "\n\n"
                );
        }
        private void StoreKeyBytes()
        {
            index = line.IndexOf(keyBytesS);
            if (index != -1)
            {
                line = line.Substring(index + keyBytesS.Length);
                line = line.Replace(" ", "");
                if (line != "")
                {
                    Key = new byte[line.Length / 2];
                    // Line = 01 HB 7J ---> 01HB7J
                    for (int i = 0; i < line.Length; i += 2)
                    {
                        Key[i / 2] = Convert.ToByte(line.Substring(i, 2), 16);
                    }
                }
            }
            else
            {
                Console.WriteLine("Key bytes not found in " + configFile);
            }
        }
        private void StoreKeyString()
        {
            index = line.IndexOf(keyStringS);
            if (index != -1)
            {
                line = line.Substring(index + keyStringS.Length);
                startIndex = line.IndexOf("\"");
                endIndex = line.LastIndexOf("\"");
                if (startIndex != -1 && endIndex != -1 && startIndex < endIndex)
                {
                    line = line.Substring(startIndex + 1, endIndex - startIndex - 1);
                    if (line != "")
                    {
                        Key = Encoding.UTF8.GetBytes(line); // UTF8, each character is represented as a byte
                    }            
                }           
            }
            else
            {
                Console.WriteLine("Key string not found in " + configFile);
            }
        }
        private void StorePlaintext()
        {
            index = line.IndexOf(plaintextS);
            if (index != -1)
            {
                line = line.Substring(index + plaintextS.Length);
                startIndex = line.IndexOf("\"");
                endIndex = line.LastIndexOf("\"");
                if (startIndex != -1 && endIndex != -1 && startIndex < endIndex)
                {
                    Plaintext = line.Substring(startIndex + 1, endIndex - startIndex -1);
                }
            }
            else
            {
                Console.WriteLine("Plaintext not found in " + configFile);
            }
        }
    }
    internal class GaloisField
    {
        private static byte[] logTable;
        private static byte[] antilogTable;
        internal GaloisField()
        {
            logTable = new byte[]
            {
                0x00, 0xff, 0xc8, 0x08, 0x91, 0x10, 0xd0, 0x36,
                0x5a, 0x3e, 0xd8, 0x43, 0x99, 0x77, 0xfe, 0x18,
                0x23, 0x20, 0x07, 0x70, 0xa1, 0x6c, 0x0c, 0x7f,
                0x62, 0x8b, 0x40, 0x46, 0xc7, 0x4b, 0xe0, 0x0e,
                0xeb, 0x16, 0xe8, 0xad, 0xcf, 0xcd, 0x39, 0x53,
                0x6a, 0x27, 0x35, 0x93, 0xd4, 0x4e, 0x48, 0xc3,
                0x2b, 0x79, 0x54, 0x28, 0x09, 0x78, 0x0f, 0x21,
                0x90, 0x87, 0x14, 0x2a, 0xa9, 0x9c, 0xd6, 0x74,
                0xb4, 0x7c, 0xde, 0xed, 0xb1, 0x86, 0x76, 0xa4,
                0x98, 0xe2, 0x96, 0x8f, 0x02, 0x32, 0x1c, 0xc1,
                0x33, 0xee, 0xef, 0x81, 0xfd, 0x30, 0x5c, 0x13,
                0x9d, 0x29, 0x17, 0xc4, 0x11, 0x44, 0x8c, 0x80,
                0xf3, 0x73, 0x42, 0x1e, 0x1d, 0xb5, 0xf0, 0x12,
                0xd1, 0x5b, 0x41, 0xa2, 0xd7, 0x2c, 0xe9, 0xd5,
                0x59, 0xcb, 0x50, 0xa8, 0xdc, 0xfc, 0xf2, 0x56,
                0x72, 0xa6, 0x65, 0x2f, 0x9f, 0x9b, 0x3d, 0xba,
                0x7d, 0xc2, 0x45, 0x82, 0xa7, 0x57, 0xb6, 0xa3,
                0x7a, 0x75, 0x4f, 0xae, 0x3f, 0x37, 0x6d, 0x47,
                0x61, 0xbe, 0xab, 0xd3, 0x5f, 0xb0, 0x58, 0xaf,
                0xca, 0x5e, 0xfa, 0x85, 0xe4, 0x4d, 0x8a, 0x05,
                0xfb, 0x60, 0xb7, 0x7b, 0xb8, 0x26, 0x4a, 0x67,
                0xc6, 0x1a, 0xf8, 0x69, 0x25, 0xb3, 0xdb, 0xbd,
                0x66, 0xdd, 0xf1, 0xd2, 0xdf, 0x03, 0x8d, 0x34,
                0xd9, 0x92, 0x0d, 0x63, 0x55, 0xaa, 0x49, 0xec,
                0xbc, 0x95, 0x3c, 0x84, 0x0b, 0xf5, 0xe6, 0xe7,
                0xe5, 0xac, 0x7e, 0x6e, 0xb9, 0xf9, 0xda, 0x8e,
                0x9a, 0xc9, 0x24, 0xe1, 0x0a, 0x15, 0x6b, 0x3a,
                0xa0, 0x51, 0xf4, 0xea, 0xb2, 0x97, 0x9e, 0x5d,
                0x22, 0x88, 0x94, 0xce, 0x19, 0x01, 0x71, 0x4c,
                0xa5, 0xe3, 0xc5, 0x31, 0xbb, 0xcc, 0x1f, 0x2d,
                0x3b, 0x52, 0x6f, 0xf6, 0x2e, 0x89, 0xf7, 0xc0,
                0x68, 0x1b, 0x64, 0x04, 0x06, 0xbf, 0x83, 0x38
            };
            antilogTable = new byte[]
            {
                0x01, 0xe5, 0x4c, 0xb5, 0xfb, 0x9f, 0xfc, 0x12,
                0x03, 0x34, 0xd4, 0xc4, 0x16, 0xba, 0x1f, 0x36,
                0x05, 0x5c, 0x67, 0x57, 0x3a, 0xd5, 0x21, 0x5a,
                0x0f, 0xe4, 0xa9, 0xf9, 0x4e, 0x64, 0x63, 0xee,
                0x11, 0x37, 0xe0, 0x10, 0xd2, 0xac, 0xa5, 0x29,
                0x33, 0x59, 0x3b, 0x30, 0x6d, 0xef, 0xf4, 0x7b,
                0x55, 0xeb, 0x4d, 0x50, 0xb7, 0x2a, 0x07, 0x8d,
                0xff, 0x26, 0xd7, 0xf0, 0xc2, 0x7e, 0x09, 0x8c,
                0x1a, 0x6a, 0x62, 0x0b, 0x5d, 0x82, 0x1b, 0x8f,
                0x2e, 0xbe, 0xa6, 0x1d, 0xe7, 0x9d, 0x2d, 0x8a,
                0x72, 0xd9, 0xf1, 0x27, 0x32, 0xbc, 0x77, 0x85,
                0x96, 0x70, 0x08, 0x69, 0x56, 0xdf, 0x99, 0x94,
                0xa1, 0x90, 0x18, 0xbb, 0xfa, 0x7a, 0xb0, 0xa7,
                0xf8, 0xab, 0x28, 0xd6, 0x15, 0x8e, 0xcb, 0xf2,
                0x13, 0xe6, 0x78, 0x61, 0x3f, 0x89, 0x46, 0x0d,
                0x35, 0x31, 0x88, 0xa3, 0x41, 0x80, 0xca, 0x17,
                0x5f, 0x53, 0x83, 0xfe, 0xc3, 0x9b, 0x45, 0x39,
                0xe1, 0xf5, 0x9e, 0x19, 0x5e, 0xb6, 0xcf, 0x4b,
                0x38, 0x04, 0xb9, 0x2b, 0xe2, 0xc1, 0x4a, 0xdd,
                0x48, 0x0c, 0xd0, 0x7d, 0x3d, 0x58, 0xde, 0x7c,
                0xd8, 0x14, 0x6b, 0x87, 0x47, 0xe8, 0x79, 0x84,
                0x73, 0x3c, 0xbd, 0x92, 0xc9, 0x23, 0x8b, 0x97,
                0x95, 0x44, 0xdc, 0xad, 0x40, 0x65, 0x86, 0xa2,
                0xa4, 0xcc, 0x7f, 0xec, 0xc0, 0xaf, 0x91, 0xfd,
                0xf7, 0x4f, 0x81, 0x2f, 0x5b, 0xea, 0xa8, 0x1c,
                0x02, 0xd1, 0x98, 0x71, 0xed, 0x25, 0xe3, 0x24,
                0x06, 0x68, 0xb3, 0x93, 0x2c, 0x6f, 0x3e, 0x6c,
                0x0a, 0xb8, 0xce, 0xae, 0x74, 0xb1, 0x42, 0xb4,
                0x1e, 0xd3, 0x49, 0xe9, 0x9c, 0xc8, 0xc6, 0xc7,
                0x22, 0x6e, 0xdb, 0x20, 0xbf, 0x43, 0x51, 0x52,
                0x66, 0xb2, 0x76, 0x60, 0xda, 0xc5, 0xf3, 0xf6,
                0xaa, 0xcd, 0x9a, 0xa0, 0x75, 0x54, 0x0e, 0x01
            };
        }
        internal byte MultiplicativeInverse(byte b)
        {
            if (b == 0) // Zero maps to itself
            {
                return 0;
            }
            else
            {
                byte logB = logTable[b];
                return antilogTable[255 - logB];
            }
        }
        internal byte AffineTransformation(byte s, byte x)
        {
            for (int i = 0; i < 4; i++)
            {
                s = (byte)((s << 1) | (s >> 7));
                x ^= s;
            }
            x ^= 0x63;
            return x;
        }
        internal byte Rcon(int i)
        {
            byte c = 1;
            if (i == 0)
            {
                return 0;
            }
            while (i != 1)
            {
                c = Multiply(c, 2);
                i--;
            }
            return c;
        }
        internal byte Multiply(byte a, byte b)
        {
            byte product = 0;
            byte carry;
            for (int i = 0; i < 8; i++)
            {
                if ((b & 1) == 1) // Check if LSB is set
                {
                    product ^= a;
                }
                carry = (byte)(a & 0x80); // Mask with 1000000
                a <<= 1; // Rotate 1 bit to left, ignoring the high bit, making low bit 0
                if (carry == 0x80)
                {
                    a ^= 0x1b;
                }
                b >>= 1; // Rotate 1 bit to right, ignoring the low bit, making high bit 0
            }
            return product;
        }
        internal byte ApplySbox(byte b)
        {
            byte s, x;
            s = x = MultiplicativeInverse(b);
            return AffineTransformation(s, x);
        }
    }
    internal class KeyExpansion
    {
        internal byte[] ExpandedKey { get; }
        private byte[] key;
        private byte[] word;
        private int byteCounter;
        private int i;
        private GaloisField GF;
        private Config config;
        internal KeyExpansion(byte[] key)
        {
            config = new Config();
            GF = new GaloisField();
            ExpandedKey = new byte[176];
            this.key = key;
            word = new byte[4];
            byteCounter = 16;
            i = 1;
            Array.Copy(this.key, ExpandedKey, 16);
            while (byteCounter < 176)
            {
                for (int a = 0; a < 4; a++)
                {
                    word[a] = ExpandedKey[byteCounter - 4 + a];
                }
                if (byteCounter % 16 == 0)
                {
                    RotWord(word);
                    for (int a = 0; a < 4; a++)
                    {
                        word[a] = GF.ApplySbox(word[a]);
                    }
                    word[0] ^= GF.Rcon(i);
                    i++;
                }
                for (int a = 0; a < 4; a++)
                {
                    ExpandedKey[byteCounter] = (byte)(ExpandedKey[byteCounter - 16] ^ word[a]);
                    byteCounter++;
                }
            }
            File.AppendAllText(
                config.Path + config.outputFiles[0],
                "# Key Expansion #\n" + Convert.ToHexString(ExpandedKey) + "\n\n"
             );
        }
        private void RotWord(byte[] word) // Circular rotate 8 bits to the left
        {
            byte b = word[0];
            for (int i = 0; i < 3; i++)
            {
                word[i] = word[i + 1];
            }
            word[3] = b;
        }
    }
    internal class Block
    {
        internal int Size { get; }
        private byte[,] block;
        private byte padding;
        internal byte this[int i, int j]
        {
            get { return block[i, j]; }
            set { block[i, j] = value; }
        }
        internal Block(byte[] plaintextBytes)
        {
            // Contents of a block
            //  [0,0] [0,1] [0,2] [0,3]
            //  [1,0] [1,1] [1,2] [1,3]
            //  ...
            //  [3,0,] [3,1] [3,2] [3,3]
            Size = 4;
            block = new byte[4, 4];
            int index = 0;
            for (int i = 0; i < Size; i++)
            {
                for (int j = 0; j < Size; j++)
                {
                    if (index < plaintextBytes.Length) // check if block can't be filled anymore
                    {
                        block[i, j] = plaintextBytes[index];
                        index++;
                    }
                    else
                    {
                        padding = (byte)(16 - index);
                        block[i, j] = padding;
                    }
                }
            }
        }
        internal void WriteBlock(string path, Block block)
        {
            for (int i = 0; i < block.Size; i++)
            {
                for (int j = 0; j < block.Size; j++)
                {
                    File.AppendAllText(
                        path,
                        block[j, i].ToString("X2") + " "
                    );
                }
                File.AppendAllText(path, "\n");
            }
            File.AppendAllText(path, "\n\n");
        }
    }
    internal class Encryption
    {
        private int counter;
        internal Block AddRoundKey(Block block, byte[] expandedKey)
        {
            counter = 0;
            for (int i = 0; i < block.Size; i++)
            {
                for (int j = 0; j < block.Size; j++)
                {
                    block[i, j] = (byte)(block[i, j] ^ expandedKey[counter]);
                    counter++;
                }
            }
            return block;
        }
        internal Block ShiftRows(Block block, int n)
        {
            if (n == 4)
            {
                return block;
            }
            byte[] row = new byte[block.Size];
            byte[] temp = new byte[row.Length];
            for (int i = 0; i < row.Length; i++) // Define row
            {
                row[i] = block[i, n];
            }
            for (int i = 0; i < n; i++) // Copy
            {
                temp[i] = row[i];
            }
            for (int i = 0; i < row.Length - n; i++) // Shift
            {
                row[i] = row[i + n];
            }
            for (int i = 0; i < n; i++) // Paste
            {
                row[row.Length - n + i] = temp[i];
            }
            for (int i = 0; i < row.Length; i++) // Insert row
            {
                block[i,n] = row[i];
            }
            n += 1;
            return ShiftRows(block, n);
        }
        internal byte[] MixColumn(byte[] column)
        {
            GaloisField GF = new GaloisField();
            // 2 3 1 1
            // 1 2 3 1 
            // 1 1 2 3
            // 3 1 1 2

            // AA
            // BB
            // CC
            // DD

            byte[] columnCopy = new byte[4];
            byte[] b = new byte[4];
            byte c;
            byte h;

            for (c = 0; c < 4; c++)
            {
                columnCopy[c] = column[c];
            }

            column[0] = (byte)(GF.Multiply(columnCopy[0], 2) ^ GF.Multiply(columnCopy[3], 1) ^ GF.Multiply(columnCopy[2], 1) ^ GF.Multiply(columnCopy[1], 3)); // (AA * 2) + (BB * 1) + (CC * 1) + (DD * 3)
            column[1] = (byte)(GF.Multiply(columnCopy[1], 2) ^ GF.Multiply(columnCopy[0], 1) ^ GF.Multiply(columnCopy[3], 1) ^ GF.Multiply(columnCopy[2], 3)); // 3 2 1 1
            column[2] = (byte)(GF.Multiply(columnCopy[2], 2) ^ GF.Multiply(columnCopy[1], 1) ^ GF.Multiply(columnCopy[0], 1) ^ GF.Multiply(columnCopy[3], 3)); // 1 3 2 1
            column[3] = (byte)(GF.Multiply(columnCopy[3], 2) ^ GF.Multiply(columnCopy[2], 1) ^ GF.Multiply(columnCopy[1], 1) ^ GF.Multiply(columnCopy[0], 3)); // 3 1 1 2

            return column;
        }
    }
    internal class Program
    {
        private static int roundBytes;
        private static int counter;
        private static int numberOfBlocks;
        private static byte[] plaintextBytesSliced;
        private static byte[] plaintextBytes;
        private static byte[] roundArray;
        private static byte[] column;
        private static Block[] plaintextBlocks;
        private static Config config;
        private static KeyExpansion key;
        private static Encryption encrypt;
        private static GaloisField GF;
        
        private static void FillBlocks()
        {
            numberOfBlocks = (config.Plaintext.Length / 16);
            if (config.Plaintext.Length % 16 != 0)
            {
                numberOfBlocks += 1;
            }
            plaintextBlocks = new Block[numberOfBlocks];
            counter = 0;
            for (int i = 0; i < plaintextBlocks.Length; i++) // Fill plaintextBlocks with plaintext
            {
                plaintextBytesSliced = new byte[plaintextBytes.Length - counter];
                plaintextBytesSliced = plaintextBytes[counter..];
                plaintextBlocks[i] = new Block(plaintextBytesSliced);
                counter += 16;
            }
            File.AppendAllText(config.Path + config.outputFiles[0], "# All blocks #\n");
            foreach (Block block in plaintextBlocks)
            {
                block.WriteBlock(config.Path + config.outputFiles[0], block);
            }
        }
        private static void ConvertToPlaintextBytes()
        {
            plaintextBytes = Encoding.UTF8.GetBytes(config.Plaintext); // UTF8, each character is represented as a byte
            File.AppendAllText(
                config.Path + config.outputFiles[0],
                "# Plaintext in UTF8 bytes #\n" + Convert.ToHexString(plaintextBytes) + "\n\n"
            );
        }
        private static void Main(string[] args)
        {
            var sw = new System.Diagnostics.Stopwatch();
            sw.Start();

            config = new Config();
            key = new KeyExpansion(config.Key);
            encrypt = new Encryption();
            GF = new GaloisField();
            roundArray = new byte[16];

            ConvertToPlaintextBytes();

            FillBlocks();

            // For each block
            // 10 rounds !!
            for (int blockNum = 0; blockNum < numberOfBlocks; blockNum++)
            {
                roundBytes = 0;
                // Add round key 1
                Array.Copy(key.ExpandedKey, roundBytes, roundArray, 0, 16); // source, index, destination, length
                plaintextBlocks[blockNum] = encrypt.AddRoundKey(plaintextBlocks[blockNum], roundArray);
                
                for (int round = 1; round < 10; round++) // 9 rounds
                {
                    File.AppendAllText(config.Path + config.outputFiles[round], "# Input blocks #\n");
                    foreach (Block block in plaintextBlocks)
                    {
                        block.WriteBlock(config.Path + config.outputFiles[round], block);
                    }

                    // Sub bytes
                    for (int i = 0; i < plaintextBlocks[blockNum].Size; i++)
                    {
                        for (int j = 0; j < plaintextBlocks[blockNum].Size; j++)
                        {
                            plaintextBlocks[blockNum][i, j] = GF.ApplySbox(plaintextBlocks[blockNum][i, j]);
                        }
                    }
                    File.AppendAllText(config.Path + config.outputFiles[round], "# Sub bytes #\n");
                    foreach (Block block in plaintextBlocks)
                    {
                        block.WriteBlock(config.Path + config.outputFiles[round], block);
                    }

                    // Shift rows
                    plaintextBlocks[blockNum] = encrypt.ShiftRows(plaintextBlocks[blockNum], 0);
                    File.AppendAllText(config.Path + config.outputFiles[round], "# Shift rows #\n");
                    foreach (Block block in plaintextBlocks)
                    {
                        block.WriteBlock(config.Path + config.outputFiles[round], block);
                    }

                    // Mix columns
                    column = new byte[4];

                    for (int a = 0; a < 4; a++)
                    {
                        for (int i = 0; i < 4; i++)
                        {
                            column[i] = plaintextBlocks[blockNum][a, i];
                        }
                        column = encrypt.MixColumn(column);

                        for (int i = 0; i < 4; i++)
                        {
                            plaintextBlocks[blockNum][a, i] = column[i];
                        }
                    }

                    File.AppendAllText(config.Path + config.outputFiles[round], "# Mix columns #\n");
                    foreach (Block block in plaintextBlocks)
                    {
                        block.WriteBlock(config.Path + config.outputFiles[round], block);
                    }

                    // Add round key
                    roundBytes += 16;
                    Array.Copy(key.ExpandedKey, roundBytes, roundArray, 0, 16);
                    plaintextBlocks[blockNum] = encrypt.AddRoundKey(plaintextBlocks[blockNum], roundArray);
                    File.AppendAllText(config.Path + config.outputFiles[round], "# Add round key #\n");
                    foreach (Block block in plaintextBlocks)
                    {
                        block.WriteBlock(config.Path + config.outputFiles[round], block);
                    }
                }

                for (int i = 0; i < plaintextBlocks[blockNum].Size; i++)
                {
                    for (int j = 0; j < plaintextBlocks[blockNum].Size; j++)
                    {
                        plaintextBlocks[blockNum][i, j] = GF.ApplySbox(plaintextBlocks[blockNum][i, j]);
                    }
                }

                plaintextBlocks[blockNum] = encrypt.ShiftRows(plaintextBlocks[blockNum], 0);

                roundBytes += 16;
                Array.Copy(key.ExpandedKey, roundBytes, roundArray, 0, 16);
                plaintextBlocks[blockNum] = encrypt.AddRoundKey(plaintextBlocks[blockNum], roundArray);
            }

            foreach (Block block in plaintextBlocks)
            {
                block.WriteBlock(config.Path + config.outputFiles[11], block);
            }

            /* Test mix columns
            byte[] testV = new byte[] {
                0xdb, 0x13, 0x53, 0x45,
                0xf2, 0x0a, 0x22, 0x5c,
                0x01, 0x01, 0x01, 0x01,
                0xc6, 0xc6, 0xc6, 0xc6
            };
            Block blockFAKE = new Block(testV);
            blockFAKE.WriteBlock("C:\\Users\\Tristan\\source\\repos\\REAL AES PROJECT\\AES\\Files\\test.txt", blockFAKE);

            byte[] col = new byte[4];

            for (int a = 0; a < 4; a++)
            {
                for (int i = 0; i < 4; i++)
                {
                    col[i] = blockFAKE[a, i];
                }
                col = encrypt.MixColumn(col);
                for (int i = 0; i < 4; i++)
                {
                    blockFAKE[a, i] = col[i];
                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Console.Write(blockFAKE[j,i].ToString("X2") + " ");
                }
                Console.Write("\n");
            }*/
            /* Test the ShifitRows step
            byte[] test = new byte[]
            {
                0xdb, 0x00, 0x00, 0x00,
                0x13, 0x00, 0x00, 0x00,
                0x53, 0x00, 0x00, 0x00,
                0x45, 0x00, 0x00, 0x00
            };
            Block blockFAKE = new Block(test);
            Encryption encryptFAKE = new Encryption();
            blockFAKE = encryptFAKE.ShiftRows(blockFAKE, 0);
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Console.Write(blockFAKE[i,j].ToString("X2") + " ");
                }
                Console.Write("\n");
            }*/
            /* How to write to file
            File.AppendAllText(config.path, "# After 1st round key XOR #\n");
            for (int i = 0; i < numberOfBlocks; i++)
            {
                plaintextBlocks[i].WriteBlock(config.path, plaintextBlocks[i]);
            }*/

            sw.Stop();
            
            Console.WriteLine($"Execution time: {sw.ElapsedMilliseconds} ms");

            Console.ReadLine();
        }
    }
}