﻿using System.Diagnostics.Metrics;
using System.Reflection;
using System.Text;

namespace AES
{
    internal class Config
    {
        private string line;
        private string endS;
        private string keyS;
        private string plaintextS;
        private string modeS;
        private int index;
        private string hexPrefix;
        private byte b;
        private int startIndex;
        private int endIndex;

        internal string path { get; }
        internal byte[] Key { get; set; }
        internal string Plaintext { get; set; }
        internal string Mode { get; set; }
        internal Config()
        {
            endS = "# End #";
            keyS = "key:";
            plaintextS = "plaintext:";
            modeS = "mode:";
            hexPrefix = "0x";
            Key = new byte[16];
            path = "C:\\Users\\Tristan\\source\\repos\\REAL AES PROJECT\\AES\\output.txt";
            if (File.Exists(path))
            {
                File.Delete(path);
                File.WriteAllText(path, string.Empty);
            }
            else
            {
                File.WriteAllText(path, string.Empty);
            }
            try
            {
                StreamReader sr = new StreamReader("C:\\Users\\Tristan\\source\\repos\\REAL AES PROJECT\\AES\\config.txt");
                while (line != endS)
                {
                    line = sr.ReadLine();
                    if (line.StartsWith(keyS))
                    {
                        StoreKey();
                    }
                    else if (line.StartsWith(plaintextS))
                    {
                        StorePlaintext();
                    }
                    else if (line.StartsWith(modeS))
                    {
                        StoreMode();
                    }
                }
                sr.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine("Exception: " + e.Message);
            }
        }
        private void StoreKey()
        {
            index = line.IndexOf(keyS);
            if (index != -1)
            {
                line = line.Substring(index + keyS.Length);
                line = Format(line);
                // Line == 01 HB 7J ---> 01HB7J
                for (int i = 0; i < Key.Length; i++)
                {
                    b = Convert.ToByte(
                        hexPrefix + line[i] + line[i + 1],
                        16
                    );
                    Key[i] = b;
                }
            }
            else
            {
                Console.WriteLine("Key section missing from config file");
            }
        }
        private void StorePlaintext()
        {
            index = line.IndexOf(plaintextS);
            if (index != -1)
            {
                Plaintext = line.Substring(index + plaintextS.Length);
                startIndex = Plaintext.IndexOf("\"");
                endIndex = Plaintext.LastIndexOf("\"");
                if (startIndex != -1 && endIndex != -1 && startIndex < endIndex)
                {
                    Plaintext = Plaintext.Substring(startIndex + 1, endIndex - startIndex -1);
                }
            }
            else
            {
                Console.WriteLine("Plaintext section missing from config file");
            }
        }
        private void StoreMode()
        {
            index = line.IndexOf(modeS);
            if (index != -1)
            {
                Mode = line.Substring(index + modeS.Length);
                Mode = Format(Mode);
            }
            else
            {
                Console.WriteLine("Mode section missing from config file");
            }
        }
        private string Format(string input)
        {
            return input.Replace(" ", "");
        }
    }
    internal class GaloisField
    {
        private static byte[] logTable = new byte[]
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
        private static byte[] antilogTable = new byte[]
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
    }
    internal class KeyExpansion
    {
        internal byte[] ExpandedKey { get; }
        private byte[] key;
        private byte[] word;
        private int byteCounter;
        private int i;
        private GaloisField GF;
        internal KeyExpansion(byte[] originalKey)
        {
            GF = new GaloisField();
            ExpandedKey = new byte[176];
            key = originalKey;
            word = new byte[4];
            byteCounter = 16;
            i = 1;
            Array.Copy(key, ExpandedKey, 16);
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
                        word[a] = ApplySbox(word[a]);
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
        private byte ApplySbox(byte b)
        {
            byte s, x;
            s = x = GF.MultiplicativeInverse(b);
            return GF.AffineTransformation(s, x);
        }
    }
    internal class Block
    {
        internal int Size { get; }
        private byte[,] block;
        internal byte this[int i, int j]
        {
            get { return block[i, j]; }
            set { block[i, j] = value; }
        }
        internal Block(byte[] plaintextBytes)
        {
            Size = 4;
            block = new byte[4, 4];
            int index = 0; // check if block can't be filled anymore
            for (int i = 0; i < Size; i++)
            {
                for (int j = 0; j < Size; j++)
                {
                    if (index < plaintextBytes.Length)
                    {
                        block[i, j] = plaintextBytes[index];
                        index++;
                    }
                    else
                    {
                        block[i, j] = 0; // 0 = null
                    }
                }
            }
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
        internal byte SubByte(byte b)
        {
            byte[,] sBox = new byte[,]
            {
                // 0    1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
                {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76}, // 0
                {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0}, // 1
                {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15}, // 2
                {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75}, // 3
                {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84}, // 4
                {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF}, // 5
                {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8}, // 6
                {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2}, // 7
                {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73}, // 8
                {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB}, // 9
                {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79}, // A
                {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08}, // B
                {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A}, // C
                {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E}, // D
                {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF}, // E
                {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}  // F
            };
            // Extract the row and column indices from the input byte
            int row = (b >> 4) & 0x0F;    // First 4 bits represent the row
            int col = b & 0x0F;           // Last 4 bits represent the column
            return sBox[row, col];
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
                row[i] = block[n, i];
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
                block[n, i] = row[i];
            }
            n += 1;
            return ShiftRows(block, n);
        }
        internal Block MixColumn(Block block)
        {
            byte[] a = new byte[4];
            byte[] b = new byte[4];
            byte c;
            byte h;

            for (c = 0; c < 4; c++)
            {
                a[c] = block[c,0];
                h = (byte)(block[c,0] & 0x80); // hi bit
                b[c] = (byte)(block[c,0] << 1);
                if (h == 0x80)
                    b[c] ^= 0x1b; // Rijndael's Galois field
            }

            block[0,0] = (byte)(b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]);
            block[1,0] = (byte)(b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]);
            block[2,0] = (byte)(b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]);
            block[3,0] = (byte)(b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]);
            return block;
        }
    }

    internal class Program
    {
        private static int roundBytes;
        private static int counter;
        private static int numberOfBlocks;
        private static byte[] plaintextBytesSliced;
        private static byte[] plaintextBytes;
        private static Block[] plaintextBlocks;
        private static Config config;
        private static KeyExpansion key;
        static void Main(string[] args)
        {
            config = new Config();
            key = new KeyExpansion(config.Key);
            File.AppendAllText(
                config.path,
                "# Key Expansion #\n" +Convert.ToHexString(key.ExpandedKey) + "\n\n"
             );

            plaintextBytes = Encoding.UTF8.GetBytes(config.Plaintext); // UTF8, each character is represented as a byte
            File.AppendAllText(
                config.path,
                "# Plaintext in UTF8 bytes #\n" + Convert.ToHexString(plaintextBytes) + "\n\n"
            );

            numberOfBlocks = (config.Plaintext.Length / 16) + 1;
            plaintextBlocks = new Block[numberOfBlocks];
            counter = 0;

            for (int i = 0; i < plaintextBlocks.Length; i++) // Fill plaintextBlocks with plaintext
            {
                plaintextBytesSliced = new byte[plaintextBytes.Length - counter];
                plaintextBytesSliced = plaintextBytes[counter..];
                plaintextBlocks[i] = new Block(plaintextBytesSliced);
                counter += 16;
            }
            File.AppendAllText(config.path, "# All blocks #\n");
            for (int a = 0; a < numberOfBlocks; a++)
            {
                for (int i = 0; i < plaintextBlocks[0].Size; i++)
                {
                    for (int j = 0; j < plaintextBlocks[0].Size; j++)
                    {
                        File.AppendAllText(
                            config.path,
                            plaintextBlocks[a][i, j].ToString("X2") + " "
                        );
                    }
                    File.AppendAllText(config.path, "\n");
                }
                File.AppendAllText(config.path, "\n\n");
            }
            // Console.WriteLine(plaintextBlocks[0][1, 2]);

            roundBytes = 0;
            Encryption encrypt = new Encryption();
            byte[] roundArray = new byte[16];

            for (int a = 0; a < numberOfBlocks; a++)
            {
                // Sub bytes
                for (int i = 0; i < plaintextBlocks[a].Size; i++)
                {
                    for (int j = 0; j < plaintextBlocks[a].Size; j++)
                    {
                        plaintextBlocks[a][i, j] = encrypt.SubByte(plaintextBlocks[a][i, j]);
                    }
                }

                // Shift rows
                plaintextBlocks[a] = encrypt.ShiftRows(plaintextBlocks[a], 0);
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

                // Mix column
                plaintextBlocks[0] = encrypt.MixColumn(plaintextBlocks[0]);
                /* Test the MixColumn step
                byte[] test = new byte[]
                {
                    0xdb, 0x00, 0x00, 0x00,
                    0x13, 0x00, 0x00, 0x00,
                    0x53, 0x00, 0x00, 0x00,
                    0x45, 0x00, 0x00, 0x00
                };
                Block blockFAKE = new Block(test);
                Encryption encryptFAKE = new Encryption();
                blockFAKE = encrypt.MixColumn(blockFAKE);
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        Console.Write(blockFAKE[i,j] + " ");
                    }
                    Console.Write("\n");
                }*/

                // Add round key
                Array.Copy(key.ExpandedKey, roundBytes, roundArray, 0, 16);
                plaintextBlocks[a] = encrypt.AddRoundKey(plaintextBlocks[a], roundArray);
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        Console.Write(plaintextBlocks[0][i, j].ToString("X2") + " ");
                    }
                }
            }

            Console.ReadLine();
        }
    }
}