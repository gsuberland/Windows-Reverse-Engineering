//Finds structures that have a particular field at an offset, including in nested structures and unions.
//@author Graham Sutherland
//@category Search
//@keybinding 
//@menupath 
//@toolbar 

import java.util.Stack;
import java.util.List;
import java.util.ListIterator;
import java.util.ArrayList;
import java.util.Iterator;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;
import ghidra.program.model.address.Address;

public class FindStructuresContainingFieldAtOffset extends GhidraScript
{

	public class TypeInfo
	{
		public TypeInfo parent;
		public int offsetInParent;
		public int remainingOffset;
		public DataType struct;
		public Union union;
		public String name;
		public int depth;

		public TypeInfo(TypeInfo parent, int offsetInParent, int remainingOffset, DataType struct, Union union, String name)
		{
			this.parent = parent;
			this.offsetInParent = offsetInParent;
			this.remainingOffset = remainingOffset;
			this.struct = struct;
			this.union = union;
			this.name = name;
			this.depth = (parent == null) ? 0 : parent.depth + 1;
		}
	}
	
	private void printMatch(TypeInfo type, DataTypeComponent component)
	{
		TypeInfo baseTypeInfo = type;
		Stack<TypeInfo> typeStack = new Stack<TypeInfo>();
		while (baseTypeInfo.parent != null)
		{
			typeStack.push(baseTypeInfo);
			baseTypeInfo = baseTypeInfo.parent;
		}
		String fullName = baseTypeInfo.struct.getDataTypePath().toString();
		TypeInfo t = null;
		while(!typeStack.empty())
		{
			t = typeStack.pop();
			String name = t.name; //(t.name != null) ? t.name : t.struct.getDisplayName(); //(t.struct != null) ? t.struct.getDisplayName() : t.union.getDisplayName();
			if (name.length() == 0)
			{
				name = "[unnamed@" + t.offsetInParent + "]";
			}
			fullName += /*"[+" + t.offsetInParent + "]."*/ "." + name;
		}
		//fullName += " [" + ((t.struct != null) ? t.struct.getDisplayName() : t.union.getDisplayName()) + "]";
		println(fullName);
	}

    /**
     * @see ghidra.app.script.GhidraScript#run()
     */
    @Override
    public void run() throws Exception
	{
		if (currentProgram == null)
		{
			println("NO CURRENT PROGRAM");
			return;
		}
		
		DataTypeManager dtm = currentProgram.getDataTypeManager();
		int maxSize = askInt("Struct size", "Enter maximum struct size: ");
		int targetFieldOffset = askInt("Field offset", "Enter offset of field in struct: ");
		String targetFieldTypeName = askString("Struct size", "Enter field type name (search matches type names containing this string): ");
		
		// add all structs to type info collection
		List<TypeInfo> typesInfo = new ArrayList<TypeInfo>();
		Iterator<Structure> structures = dtm.getAllStructures();
		while (structures.hasNext())
		{
			Structure structure = structures.next();
			typesInfo.add(new TypeInfo(null, 0, targetFieldOffset, structure, null, null));
		}
		
		// iterate through types to find ones that match our expectations
		ListIterator<TypeInfo> typeInfoIterator = typesInfo.listIterator();
		while (typeInfoIterator.hasNext())
		{
			TypeInfo typeInfo = typeInfoIterator.next();
			if (typeInfo.offsetInParent < 0 || typeInfo.remainingOffset < 0)
			{
				println("ERROR: NEGATIVE OFFSET!");
			}
			
			// check if the type is nested (i.e. we started looking at a type and now we're looking at a field type)
			boolean isNested = false;
			if (typeInfo.parent != null)
			{
				isNested = true;
			}
			
			if (typeInfo.depth > 0)
			{
				//println("Depth: " + typeInfo.depth);
			}
			
			// get the struct or union length
			int fieldLength = typeInfo.struct != null ? typeInfo.struct.getLength() : typeInfo.union.getLength();
			
			// if this is not a child field we're investigating, check if the size is within the bounds set as part of the search
			if (!isNested && fieldLength > maxSize)
			{
				//println("Skipping " + typeInfo.struct.getDisplayName() + " because it is too large (" + typeInfo.struct.getLength() + ").");
				if (typeInfo.depth > 0)
				{
					println("ERROR: DEPTH > 0");
				}
				continue;
			}
			
			int targetOffsetInType = typeInfo.remainingOffset;
			/*if (isNested)
			{
				targetOffsetInType = targetFieldOffset - typeInfo.remainingOffset;
			}*/
			
			// if this is a struct, check through its fields
			if (typeInfo.struct != null && typeInfo.struct instanceof Structure)
			{
				Structure structure = (Structure)typeInfo.struct;
				
				/*boolean isKTHREAD = structure.getDisplayName().contains("_KTHREAD");
				if (isKTHREAD)
				{
					println("Hit KTHREAD type: " + structure.getDataTypePath().toString());
				}*/
				
				// find a child component that matches the remaining offset
				DataTypeComponent componentAtOffset = structure.getComponentAt(targetOffsetInType);
				if (componentAtOffset != null)
				{
					if (componentAtOffset.getOffset() == targetOffsetInType)
					{
						// this field sits exactly at the offset we're looking for, so check if it's the right type
						if (componentAtOffset.getDataType().getDisplayName().toLowerCase().contains(targetFieldTypeName.toLowerCase()))
						{
							//println("targetOffsetInType=" + targetOffsetInType);
							String fieldName = componentAtOffset.getFieldName();
							if (fieldName == null)
							{
								fieldName = "[unnamed_field@0x" + Integer.toHexString(componentAtOffset.getOffset()) + "]";
							}
							TypeInfo match = new TypeInfo(typeInfo, componentAtOffset.getOffset(), targetOffsetInType - componentAtOffset.getOffset(), structure, null, fieldName);
							printMatch(match, componentAtOffset);
						}
					}
					
					/*if (componentAtOffset.getOffset() <= targetOffsetInType)
					{*/
						// this field is either exactly at the offset we're looking for (and therefore might have a first child field that matches) or is before the the offset we're looking for
						
						DataType componentType = componentAtOffset.getDataType();
						
						String fieldName = componentAtOffset.getFieldName();
						if (fieldName == null)
						{
							fieldName = "[unnamed_field@0x" + Integer.toHexString(componentAtOffset.getOffset()) + "]";
						}
						
						//String objectClass = (componentType instanceof Structure) ? "struct" : "union";
						
						//println("Investgating " + objectClass + " " + fieldName + " at offset 0x" + Integer.toHexString(componentAtOffset.getOffset()) + " (remaining offset = 0x" + Integer.toHexString(targetOffsetInType - componentAtOffset.getOffset()) + ")");
						
						// add to nested types to investigate
						
						if (componentType instanceof Structure)
						{
							typeInfoIterator.add(new TypeInfo(typeInfo, componentAtOffset.getOffset(), targetOffsetInType - componentAtOffset.getOffset(), (Structure)componentType, null, fieldName));
							typeInfoIterator.previous();
						}
						else if (componentType instanceof Union)
						{
							typeInfoIterator.add(new TypeInfo(typeInfo, componentAtOffset.getOffset(), targetOffsetInType - componentAtOffset.getOffset(), null, (Union)componentType, fieldName));
							typeInfoIterator.previous();
						}
						else if (componentType instanceof Composite)
						{
							println("WARNING: Unexpected type.");
							typeInfoIterator.add(new TypeInfo(typeInfo, componentAtOffset.getOffset(), targetOffsetInType - componentAtOffset.getOffset(), (Composite)componentType, null, fieldName));
							typeInfoIterator.previous();
						}
					//}
				}
				/*else if (isKTHREAD)
				{
					println("KTHREAD was ignored because it did not have a component at the required offset.");
				}*/
			}
			
			// if this is a union, check to see if any of its types 
			if (typeInfo.union != null)
			{
				//println("Processing union " + typeInfo.name);
				
				Union union = typeInfo.union;
				for (DataTypeComponent unionComponent : union.getComponents())
				{
					if (targetOffsetInType == 0)
					{
						// this field sits exactly at the offset we're looking for, so check if it's the right type
						if (unionComponent.getDataType().getDisplayName().toLowerCase().contains(targetFieldTypeName.toLowerCase()))
						{
							DataType unionComponentType = unionComponent.getDataType();
							
							String fieldName = unionComponent.getFieldName();
							if (fieldName == null)
							{
								fieldName = "[unnamed_field@0x" + Integer.toHexString(unionComponent.getOffset()) + "]";
							}
							
							TypeInfo match = null;
							if (unionComponentType instanceof Structure)
							{
								match = new TypeInfo(typeInfo, 0, 0, (Structure)unionComponentType, null, fieldName);
							}
							else if (unionComponentType instanceof Union)
							{
								match = new TypeInfo(typeInfo, 0, 0, null, (Union)unionComponentType, fieldName);
							}
							else if (unionComponentType instanceof Pointer)
							{
								match = new TypeInfo(typeInfo, 0, 0, (Pointer)unionComponentType, null, fieldName);
							}
							else if (unionComponentType instanceof Composite)
							{
								println("WARNING: Unexpected type.");
								match = new TypeInfo(typeInfo, 0, 0, unionComponentType, null, fieldName);
								//println("Found match with an instance type neither structure nor union!");
								//println(unionComponentType.toString() + " - " + unionComponentType.getClass().toString());
							}
							if (match != null)
							{
								printMatch(match, unionComponent);
							}
						}
					}
					if (unionComponent.getLength() > targetOffsetInType)
					{
						//println("Investigating union member " + unionComponent.getFieldName());
						
						DataType componentType = unionComponent.getDataType();
						
						String fieldName = unionComponent.getFieldName();
						if (fieldName == null)
						{
							fieldName = "[unnamed_field@0x" + Integer.toHexString(unionComponent.getOffset()) + "]";
						}
						
						if (componentType instanceof Structure)
						{
							typeInfoIterator.add(new TypeInfo(typeInfo, 0, typeInfo.remainingOffset, (Structure)componentType, null, fieldName));
							typeInfoIterator.previous();
						}
						else if (componentType instanceof Union)
						{
							
							typeInfoIterator.add(new TypeInfo(typeInfo, 0, typeInfo.remainingOffset, null, (Union)componentType, fieldName));
							typeInfoIterator.previous();
						}
						else if (componentType instanceof Composite)
						{
							println("WARNING: Unexpected type.");
							typeInfoIterator.add(new TypeInfo(typeInfo, 0, typeInfo.remainingOffset, (Composite)componentType, null, fieldName));
							typeInfoIterator.previous();
						}
					}
					else
					{
						//println("Skipping union member " + unionComponent.getFieldName() + " because it is too small (0x" + Integer.toHexString(unionComponent.getLength()) + " <= 0x" + Integer.toHexString(targetOffsetInType) + ")");
					}
				}
			}
		}
		println("Done.");
	}
}
