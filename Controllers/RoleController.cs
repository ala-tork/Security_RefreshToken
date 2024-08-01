using Auth.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RefreshToken.Model;
using System.Security.Claims;

namespace Auth.Controllers
{
    [Route("/api/role")]
    [ApiController]
    public class RoleController:ControllerBase
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<User> _userManager;
        public RoleController(RoleManager<IdentityRole> roleManager, UserManager<User> _userManager)
        {
            _roleManager = roleManager;
            this._userManager = _userManager;
        }

        [Authorize(Roles ="ADMIN,USER")]
        [HttpPost("/AddRole")]
        public async Task<IActionResult> addRole([FromBody] RoleDto role)
        {
            try
            {
                var roleExist = await _roleManager.FindByNameAsync(role.name);
                if (roleExist != null)
                {
                    return BadRequest("role exist");
                }
                IdentityRole roles = new IdentityRole { Name = role.name };
                var result = await _roleManager.CreateAsync(roles);
                return Ok(result);
            }         
            catch (Exception ex) { return StatusCode(500, ex.Message);
    }
}
        [Authorize(Roles = "ADMIN")]
        [HttpPost("api/AssignRoleToUser")]
        public async Task<IActionResult> assignRoleToUser([FromBody] AssignRoleToUserDto userRole)
        {
            try
            {
                if (userRole.Role == "host")
                {
                    ClaimsPrincipal currentUser = this.User;
                    bool IsHost = currentUser.IsInRole("host");
                    if (!IsHost)
                    {
                        return BadRequest("You can't assign this role, you still more small to do it");
                    }
                }
                var roleExist = await _roleManager.FindByNameAsync(userRole.Role);
                if (roleExist == null)
                {
                    var listOfRole = await _roleManager.Roles.ToListAsync();
                    string listroles = "";
                    foreach (IdentityRole r in listOfRole)
                    {
                        listroles += r.Name + " ";
                    }
                    return BadRequest("Role notFound, please choose one of there role : " + listroles);
                }
                var user = await _userManager.FindByEmailAsync(userRole.Email);
                if (user == null)
                {
                    return BadRequest("User with " + userRole.Email + " email not found");
                }
                if (userRole.Role == "host")
                {
                    await _userManager.AddToRoleAsync(user, "Admin");
                }

                var result = await _userManager.AddToRoleAsync(user, userRole.Role);

                return Ok(result);

            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
        }

}
}
