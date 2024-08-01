using System.ComponentModel.DataAnnotations;

namespace Auth.Model
{
    public class AssignRoleToUserDto
    {
        [Required]
        public string Email { get; set; }
        [Required]
        public string Role { get; set; }
    }
}
