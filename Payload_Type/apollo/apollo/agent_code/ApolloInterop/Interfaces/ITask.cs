using System.Threading.Tasks;
namespace ApolloInterop.Interfaces
{
    public interface ITask
    {
        string ID();
        void Start();
        Task CreateTasking();
        void Kill();
    }
}
