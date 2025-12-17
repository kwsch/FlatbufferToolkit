using Be.Windows.Forms;
using FlatBuffersParser;
using System;
using System.Collections.Generic;
using System.ComponentModel.Design;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace FlatbufferHelper
{
    public class FlatBufferBinWalk
    {
        private readonly BinaryReader _reader;
        private readonly Schema _schema;
        private readonly TreeView _treeView;

        public FlatBufferBinWalk(ref HexBox viewer, ref TreeView treeView, byte[] buffer, Schema schema)
        {
            _reader = new BinaryReaderTracked(new MemoryStream(buffer), viewer);
            _schema = schema;
            _treeView = treeView;
        }

        public Dictionary<string, object>? ReadRoot()
        {
            if (_schema.RootType == null)
                throw new Exception("No root_type specified in schema");
            Dictionary<string, object> root = null;
            try
            {
                var rootStruct = _schema.Structs[_schema.RootType];
                var rootOffset = ReadIntAt(0);

                var rootNode = new TreeNode(_schema.RootType);
                root = ReadTable(rootStruct, rootOffset, ref rootNode);
                _treeView.Nodes.Add(rootNode);
            }
            catch (Exception ex)
            {
                Logger.Instance.Log(ex.Message);
            }

            return root;
        }

        private Dictionary<string, object> ReadTable(StructDef structDef, long offset, ref TreeNode thisNode)
        {
            var result = new Dictionary<string, object>();

            //Read vtable
            var vtableOffset = offset - ReadIntAt(offset);
            var vtableSize = ReadUShortAt(vtableOffset);
            var tblSize = ReadUShortAt(vtableOffset+2);

            thisNode.ToolTipText = string.Format("Addr: 0x{0} | Elements: {1}", (offset).ToString("X4"), (vtableSize - 4) / 2);
            foreach (var field in structDef.Fields)
            {
                if (field.Deprecated) continue;

                var fieldVtableOffset = 4 + field.Id * 2;
                if (fieldVtableOffset >= vtableSize) continue;

                
                var fieldOffset = ReadUShortAt(vtableOffset + fieldVtableOffset);

                if (fieldOffset == 0)
                {
                    result[field.Name] = GetDefaultValue(field);
                    continue;
                }

                TreeNode elem = new TreeNode();
                elem.ToolTipText = string.Format("Addr: 0x{0}", (offset + fieldOffset).ToString("X4"));

                result[field.Name] = ReadFieldAt(field, offset + fieldOffset, ref elem);

                thisNode.Nodes.Add(elem);
            }

            return result;
        }

        private Dictionary<string, object> ReadStruct(StructDef structDef, long offset, ref TreeNode thisNode)
        {
            var result = new Dictionary<string, object>();
            
            var pos = offset;
            foreach (var field in structDef.Fields)
            {
                Seek(pos);
                if (field.Deprecated) continue;

                TreeNode elem = new TreeNode();
                elem.ToolTipText = string.Format("Addr: 0x{0}", (pos).ToString("X4"));
                
                result[field.Name] = ReadFieldAt(field, pos, ref elem);

                thisNode.Nodes.Add(elem);

                pos += GetTypeSize(field.Type.ElementType);
            }

            return result;
        }

        private object ReadFieldAt(FieldDef field, long pos, ref TreeNode node)
        {
            Seek(pos);
            
            object val = null;

            node.Text = string.Empty;
            //Everything that isnt a table/struct/vec should be shown as var:val
            //Others are var:type, with vals as children
            if (field.Type.IsScalar || field.Type.IsString)
                node.Text = field.Name + ":";
            switch (field.Type.BaseType)
            {
                case BaseType.Bool: val = _reader.ReadByte() != 0; break;
                case BaseType.Byte: val = _reader.ReadSByte(); break;
                case BaseType.UByte: val = _reader.ReadByte(); break;
                case BaseType.Short: val = _reader.ReadInt16(); break;
                case BaseType.UShort: val = _reader.ReadUInt16(); break;
                case BaseType.Int: val = _reader.ReadInt32(); break;
                case BaseType.UInt: val = _reader.ReadUInt32(); break;
                case BaseType.Long: val = _reader.ReadInt64(); break;
                case BaseType.ULong: val = _reader.ReadUInt64(); break;
                case BaseType.Float: val = _reader.ReadSingle(); break;
                case BaseType.Double: val = _reader.ReadDouble(); break;
            }
            if(val != null)
                node.Text += val.ToString();

            switch (field.Type.BaseType)
            {
                case BaseType.String: 
                    val = ReadStringAt(pos);
                    node.Text += string.Format("\"{0}\"", val); 
                    break;
                case BaseType.Vector:
                    var typeName = field.Type.ElementType == BaseType.Obj ? field.Type.StructName : field.Type.ElementType.ToString();
                    node.Text = string.Format("{0}:Vector<{1}>",field.Name, typeName);
                    val = ReadVectorAt(field, pos, ref node);
                    break;
                case BaseType.Obj:
                    node.Text = field.Type.StructName;
                    var tableOffset = pos + ReadIntAt(pos);
                    var structDef = _schema.Structs.Values.FirstOrDefault(s => s.Name == field.Type.StructName || s.Name.EndsWith("." + field.Type.StructName));

                    if (structDef != null)
                    {
                        if (structDef.IsStruct)
                            val = ReadStruct(structDef, pos, ref node);
                        else
                            val = ReadTable(structDef, tableOffset, ref node);
                    }

                    break;
            }

            return val;
        }

        private object ReadVectorAt(FieldDef field, long pos, ref TreeNode thisNode)
        {
            var vectorOffset = pos + ReadIntAt(pos);
            var length = ReadIntAt(vectorOffset);
            var dataOffset = vectorOffset + 4;

            var list = new List<object>();
            var elemSize = GetTypeSize(field.Type.ElementType);

            for (int i = 0; i < length; i++)
            {
                var elemPos = dataOffset + i * elemSize;

                var child = new TreeNode(field.Type.StructName);
                child.ToolTipText = string.Format("Addr: 0x{0}", elemPos.ToString("X4"));
                if (field.Type.ElementType == BaseType.Obj)
                {
                    var tableOffset = elemPos + ReadIntAt(elemPos);
                    var structDef = _schema.Structs.Values.FirstOrDefault(s => s.Name == field.Type.StructName || s.Name.EndsWith("." + field.Type.StructName));
                    object val = null;
                    if (structDef != null)
                    {
                        if (structDef.IsStruct)
                            val = ReadStruct(structDef, elemPos, ref child);
                        else
                            val = ReadTable(structDef, tableOffset, ref child);
                    }
                    list.Add(val);
                }
                else
                {
                    var elemField = new FieldDef
                    {
                        Type = new FbsType
                        {
                            BaseType = field.Type.ElementType,
                            StructName = field.Type.StructName
                        }
                    };
                    list.Add(ReadFieldAt(elemField, elemPos, ref child));
                }
                thisNode.Nodes.Add(child);
            }

            return list;
        }

        private string ReadStringAt(long pos)
        {
            var stringOffset = pos + ReadIntAt(pos);
            var length = ReadIntAt(stringOffset);
            Seek(stringOffset + 4);
            return Encoding.UTF8.GetString(_reader.ReadBytes((int)length));
        }

        private object GetDefaultValue(FieldDef field)
        {
            if (!string.IsNullOrEmpty(field.DefaultValue))
            {
                switch (field.Type.BaseType)
                {
                    case BaseType.Bool:
                        return field.DefaultValue != "0";
                    case BaseType.Byte:
                    case BaseType.Short:
                    case BaseType.Int:
                    case BaseType.Long:
                        return long.Parse(field.DefaultValue);
                    case BaseType.UByte:
                    case BaseType.UShort:
                    case BaseType.UInt:
                    case BaseType.ULong:
                        return ulong.Parse(field.DefaultValue);
                    case BaseType.Float:
                        return float.Parse(field.DefaultValue);
                    case BaseType.Double:
                        return double.Parse(field.DefaultValue);
                }
            }

            return field.Type.BaseType switch
            {
                BaseType.Bool => false,
                BaseType.Byte or BaseType.Short or BaseType.Int or BaseType.Long => 0L,
                BaseType.UByte or BaseType.UShort or BaseType.UInt or BaseType.ULong => 0UL,
                BaseType.Float => 0.0f,
                BaseType.Double => 0.0,
                _ => null
            };
        }

        private int GetTypeSize(BaseType type)
        {
            return type switch
            {
                BaseType.Bool or BaseType.Byte or BaseType.UByte => 1,
                BaseType.Short or BaseType.UShort => 2,
                BaseType.Int or BaseType.UInt or BaseType.Float => 4,
                BaseType.Long or BaseType.ULong or BaseType.Double => 8,
                BaseType.String or BaseType.Vector or BaseType.Obj => 4,
                _ => 0
            };
        }

        private void Seek(long pos) => _reader.BaseStream.Position = pos;
        private short ReadShortAt(long pos) { Seek(pos); return _reader.ReadInt16(); }
        private ushort ReadUShortAt(long pos) { Seek(pos); return _reader.ReadUInt16(); }
        private int ReadIntAt(long pos) { Seek(pos); return _reader.ReadInt32(); }
        private uint ReadUIntAt(long pos) { Seek(pos); return _reader.ReadUInt32(); }
        private long ReadLongAt(long pos) { Seek(pos); return _reader.ReadInt64(); }
        private ulong ReadULongAt(long pos) { Seek(pos); return _reader.ReadUInt64(); }
    }

    public class BinaryReaderTracked : BinaryReader
    {
        private readonly HexBox _viewer;

        public BinaryReaderTracked(Stream input, HexBox viewer)
            : base(input) => _viewer = viewer;

        bool HasOverlap(List<HexBox.HighlightedRegion> regions, long offset, int length)
        {
            long start = offset;
            long end = offset + length;

            int lo = 0;
            int hi = regions.Count - 1;

            while (lo <= hi)
            {
                int mid = (lo + hi) / 2;
                var r = regions[mid];

                int rStart = r.Start;
                int rEnd = r.Start + r.Length;

                if (end <= rStart)
                    hi = mid - 1;
                else if (start >= rEnd)
                    lo = mid + 1;
                else
                    return true;
            }

            return false;
        }


        private T Track<T>(int size, Color col, Func<T> read)
        {
            long pos = BaseStream.Position;
            if (true || !HasOverlap(_viewer.HighlightedRegions, pos, size)) //TODO: vtables get reused in vectors at least; also probably best to track seperates as a bitfield
            {
                _viewer.HighlightedRegions.Add(new HexBox.HighlightedRegion((int)pos, size, col));
                _viewer.HighlightedRegions.Sort((a,b) => a.Start.CompareTo(b.Start));
            }
            else
                Logger.Instance.Log(string.Format("Overlap read at 0x{0} [size=0x{1}]", pos.ToString("X"), size.ToString("X")));

            return read();
        }

        public override byte ReadByte() => Track(1, Color.Green, base.ReadByte);
        public override sbyte ReadSByte() => Track(1, Color.Green, base.ReadSByte);
        public override short ReadInt16() => Track(2, Color.CadetBlue, base.ReadInt16);
        public override ushort ReadUInt16() => Track(2, Color.CadetBlue, base.ReadUInt16);
        public override int ReadInt32() => Track(4, Color.Purple, base.ReadInt32);
        public override uint ReadUInt32() => Track(4, Color.Purple, base.ReadUInt32);
        public override long ReadInt64() => Track(8, Color.Orange, base.ReadInt64);
        public override ulong ReadUInt64() => Track(8, Color.Orange, base.ReadUInt64);
        public override float ReadSingle() => Track(4, Color.Red, base.ReadSingle);
        public override double ReadDouble() => Track(8, Color.MediumVioletRed, base.ReadDouble);

        public override byte[] ReadBytes(int count)
        {
            long pos = BaseStream.Position;
            _viewer.HighlightedRegions.Add(new HexBox.HighlightedRegion((int)pos, count, Color.MediumTurquoise));
            return base.ReadBytes(count);
        }
    }

}
