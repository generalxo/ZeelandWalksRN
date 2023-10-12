using ZeelandWalksApi.Models.Domain;

namespace ZeelandWalksApi.Repositories
{
    public interface IImageRepository
    {
        Task<Image> Upload(Image image);
    }
}
