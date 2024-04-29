namespace ApolloInterop.Interfaces
{
    public interface ICryptographySerializer : ISerializer
    {
        bool UpdateUUID(string uuid);
        bool UpdateKey(string key);

        string GetUUID();
    }
}
