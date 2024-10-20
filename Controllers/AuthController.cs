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

                if (user != null && await _userManager.CheckPasswordAsync(user, loginmodel.Password)) 
                {

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


        [HttpPut("update-user")]
        [Authorize] // Only authorized users can update their details
        public async Task<IActionResult> UpdateUser([FromBody] UpdateUserDto model)
        {
            // Get the currently authenticated user
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return NotFound("User not found");

            // Check if email needs to be updated
            if (!string.IsNullOrEmpty(model.Email) && model.Email != user.Email)
            {
                var emailExists = await _userManager.FindByEmailAsync(model.Email);
                if (emailExists != null) return BadRequest("Email is already taken");

                user.Email = model.Email;
                user.UserName = model.Email;
            }

            // Check if password update is requested
            if (!string.IsNullOrEmpty(model.CurrentPassword) && !string.IsNullOrEmpty(model.NewPassword))
            {
                if (model.NewPassword != model.ConfirmPassword)
                {
                    return BadRequest("New password and confirm password do not match.");
                }

                var passwordChangeResult = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
                if (!passwordChangeResult.Succeeded)
                {
                    return BadRequest(passwordChangeResult.Errors);
                }
            }

            var result = await _userManager.UpdateAsync(user);

            if (result.Succeeded)
            {
                return Ok("User updated successfully.");
            }

            return BadRequest(result.Errors);
        }


        [HttpPost]
        [Route("refresh")]
        public async Task<ActionResult> Refresh(TokenApiModel tokenApiModel)
        {
            if (tokenApiModel is null)
                return BadRequest("Invalid client request");

            string accessToken = tokenApiModel.AccessToken;
            string refreshToken = tokenApiModel.RefreshToken;

            var principal = _tokenService.GetPrincipalFromExpiredToken(accessToken);
            var username = principal.Identity.Name;//this is mapped to the Name claim by default

            var user = await _userManager.FindByNameAsync(username);

            if (user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
                return BadRequest("Invalid client request");

            var newAccessToken = _tokenService.GenerateAccessToken(principal.Claims);
            var newRefreshToken = _tokenService.GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            await _userManager.UpdateAsync(user);

            return Ok(new AuthenticatedResponse()
            {
                Token = newAccessToken,
                RefreshToken = newRefreshToken
            });
        }

    }
}
