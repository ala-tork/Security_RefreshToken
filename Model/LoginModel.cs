using System.ComponentModel.DataAnnotations;

namespace Auth.Model
{
    public class LoginModel
    {
        [Required(ErrorMessage = "Username can't be null")]
        public string? Username { get; set; }
        [Required(ErrorMessage ="Password can't be null")]
        public string? Password { get; set; }
    }
}
