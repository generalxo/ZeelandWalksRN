using Microsoft.AspNetCore.Identity;

namespace ZeelandWalksApi.Repositories
{
    public interface ITokenRepository
    {
        string CreateJWTToken(IdentityUser user, List<string> roles);
    }
}
