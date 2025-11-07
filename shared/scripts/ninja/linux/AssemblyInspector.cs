using System;
using System.Reflection;
using System.Linq;

class Program
{
    static void Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Usage: dotnet run <assembly-path>");
            return;
        }

        try
        {
            var assembly = Assembly.LoadFrom(args[0]);
            Console.WriteLine($"Assembly: {assembly.FullName}");
            Console.WriteLine($"Location: {assembly.Location}");
            Console.WriteLine();

            Console.WriteLine("=== ALL PUBLIC TYPES ===");
            var types = assembly.GetExportedTypes()
                .OrderBy(t => t.Namespace)
                .ThenBy(t => t.Name);

            foreach (var type in types)
            {
                Console.WriteLine($"{type.FullName}");
                
                // Check for suspicious base types
                if (type.BaseType != null)
                {
                    Console.WriteLine($"  Base: {type.BaseType.FullName}");
                }
                
                // Check interfaces
                var interfaces = type.GetInterfaces();
                if (interfaces.Length > 0)
                {
                    Console.WriteLine($"  Interfaces: {string.Join(", ", interfaces.Select(i => i.Name))}");
                }
                
                Console.WriteLine();
            }

            Console.WriteLine("=== SUMMARY ===");
            Console.WriteLine($"Total exported types: {types.Count()}");
            
            var byNamespace = types.GroupBy(t => t.Namespace);
            foreach (var ns in byNamespace)
            {
                Console.WriteLine($"{ns.Key}: {ns.Count()} types");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
}
