using Microsoft.AspNetCore.Identity;

namespace ZeelandWalksApi.Repositories
{
    public interface ITokenRepository
    {
        string CreateJwtToken(IdentityUser user, List<string> roles);
    }
}
