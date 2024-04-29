using System;
using System.Text;

namespace ApolloInterop.Utils;

public static class RecordExtensions
{
    public static string ToIndentedString(this string recordString)
    {
        if (string.IsNullOrWhiteSpace(recordString))
            return recordString;

        var sb = new StringBuilder();
        var parts = recordString.Split(new[] { '{' }, StringSplitOptions.RemoveEmptyEntries);
        
        
        //get the type name from parts[0]
        var recordName = parts[0].Trim();
        //add the type name to the string builder
        sb.AppendLine();
        sb.AppendLine(recordName);
        sb.AppendLine("{");
        
        //remove the } from the last part and update the last part
        string body = parts[^1].Trim().TrimEnd('}');
        
        var trimmedPart = body.Trim();
        var propertyValues = trimmedPart.Split(new[] { ',' });
       
        for (int i = 0; i < propertyValues.Length; i++)
        {
            var trimmedropertyLine = propertyValues[i].Trim();
            if (trimmedropertyLine.Contains("="))
            {
                //after the first property we need a line break so each property = value pair is on a new line
                if (i > 0)
                {
                    sb.AppendLine();
                }
                sb.Append($"\t{trimmedropertyLine}, ");
            }
            else
            {
                sb.Append($"{trimmedropertyLine}, ");
            }
        }
        sb.AppendLine();
        sb.AppendLine("}");

        return sb.ToString();
    }
}