using Auth.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

using Microsoft.IdentityModel.Tokens;
using RefreshToken.Dtos;
using RefreshToken.Model;
using RefreshToken.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Auth.Controllers
{
    [Route("/api/Auth")]
    [ApiController]
    public class AuthController:ControllerBase
    {
        private const string V = "admin";
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IUserService _userService;
        private readonly ITokenService _tokenService;
        public AuthController(UserManager<User> _userManager, RoleManager<IdentityRole> _roleManager, 
            IConfiguration _configuration,IUserService userService,ITokenService tokenService) 
        {
                this._userManager = _userManager;
                this._roleManager = _roleManager;
                this._configuration = _configuration;
                this._userService = userService;
                this._tokenService = tokenService;
        }

        [HttpGet, Authorize]
        public ActionResult GetMe()
        {
            var userName = _userService.GetMyName();
            var email = User.FindFirstValue(ClaimTypes.Email);
            
            return Ok(new { userName,email});
        }

        [HttpPost("/login")]
        public async Task<IActionResult> Login([FromBody]LoginModel loginmodel)
        {
            try { 
                var user =await  _userManager.FindByEmailAsync(loginmodel.Username);
                if (user == null)
                {
                    user= await _userManager.FindByNameAsync(loginmodel.Username);
                }
                Boolean test = await _userManager.CheckPasswordAsync(user, loginmodel.Password);
                if (user != null && await _userManager.CheckPasswordAsync(user, loginmodel.Password)) {

                    var userRoles = await _userManager.GetRolesAsync(user);
                    var AuthClaims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name,user?.NormalizedUserName),
                        new Claim(ClaimTypes.Email,user.Email),
                        new Claim(ClaimTypes.Role, "ADMIN"),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())

                    };
                    /*                    foreach (var role in userRoles) {
                                            AuthClaims.Add(new Claim(ClaimTypes.Role, role));

                                        }*/
                    /*                    var AuthSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
                                        var token = new JwtSecurityToken(
                                            issuer: _configuration["JWT:ValidIssuer"],
                                            audience: _configuration["JWT:ValidAudience"],
                                            expires: DateTime.Now.AddHours(7),
                                            claims: AuthClaims,
                                            signingCredentials:new SigningCredentials(AuthSigningKey,SecurityAlgorithms.HmacSha256)
                                            );*/

                    var accessToken = _tokenService.GenerateAccessToken(AuthClaims);
                    var refreshToken = _tokenService.GenerateRefreshToken();
                    user.RefreshToken = refreshToken;
                    user.RefreshTokenExpiryTime = DateTime.Now.AddDays(7);

                    await _userManager.UpdateAsync(user);

                    return Ok(new AuthenticatedResponse
                    {
                        Token = accessToken,
                        RefreshToken = refreshToken
                    });
                }
                return Unauthorized();
            }
                catch (Exception ex) { return StatusCode(500, ex.Message); 
            }
        }

        [HttpPost("/SignUp")]
        public async Task<IActionResult> SignUp([FromBody] RegisterModel registerModel)
        {
            try
            {
                var userExist = await _userManager.FindByEmailAsync(registerModel.Email);
                var userExist2 = await _userManager.FindByNameAsync(registerModel.Username);
                if (userExist2 != null)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Username already exists" });
                }
                if (userExist != null)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Email already exists" });
                }
                User user = new()
                {
                    Email = registerModel.Email,
                    UserName = registerModel.Username,
                    SecurityStamp = Guid.NewGuid().ToString()

                };


                var result = await _userManager.CreateAsync(user, registerModel.Password);
                if (!result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Something went wrong. Try Another Time!!!" });
                }

                //amelioration : créer un endpoint pour affecter le role user (est ce que ca peut affecter les performances)

                await _userManager.AddToRoleAsync(user, "user");

                return Ok(new Response { Status = "OK", Message = "User created succesfully" });


            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
        }
    }
}
