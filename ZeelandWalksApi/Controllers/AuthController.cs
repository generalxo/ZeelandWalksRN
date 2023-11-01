using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using ZeelandWalksApi.Models.DTO;
using ZeelandWalksApi.Repositories;

namespace ZeelandWalksApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ITokenRepository _tokenRepository;

        public AuthController(UserManager<IdentityUser> userManager, ITokenRepository tokenRepository)
        {
            _userManager = userManager;
            _tokenRepository = tokenRepository;
        }
        //post: api/auth/register
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequestDto registerRequestDto)
        {
            var identityUser = new IdentityUser
            {
                UserName = registerRequestDto.Username,
                Email = registerRequestDto.Username
            };
            var IdentityResult = await _userManager.CreateAsync(identityUser, registerRequestDto.Password);

            if(IdentityResult.Succeeded)
            {
                //ad role to this user
                if(registerRequestDto.Roles != null && registerRequestDto.Roles.Any())
                {
                    IdentityResult = await _userManager.AddToRolesAsync(identityUser, registerRequestDto.Roles);
                    if (IdentityResult.Succeeded)
                    {
                        return Ok("The user was registered");
                    }
                }
            }
            return BadRequest("Server error has ocurred");
        }

        //post: api/auth/login
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequestDto loginRequestDto)
        {
            var user = await _userManager.FindByEmailAsync(loginRequestDto.Username);

            if (user != null)
            {
                var checkPasswordRequest = await _userManager.CheckPasswordAsync(user, loginRequestDto.Password);
                if (checkPasswordRequest)
                {
                    //get a role for the user
                    var roles = await _userManager.GetRolesAsync(user);
                    if (roles != null)
                    {
                        //Create token
                        var jwtToken = _tokenRepository.CreateJwtToken(user, roles.ToList());
                        var response = new LoginResponseDto
                        {
                            JwtToken = jwtToken
                        };

                        return Ok(response);
                    }
                }
            }
            return BadRequest("Username or password is incorrect");
        }
    }
}
