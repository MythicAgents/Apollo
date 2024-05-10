namespace ApolloInterop.Interfaces
{
    public interface IC2ProfileManager
    {
        bool AddEgress(IC2Profile profile);
        bool AddIngress(IC2Profile profile);

        IC2Profile[] GetEgressCollection();
        IC2Profile[] GetIngressCollection();

        IC2Profile[] GetConnectedEgressCollection();
    }
}
