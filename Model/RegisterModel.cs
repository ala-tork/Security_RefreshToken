using System.ComponentModel.DataAnnotations;

namespace Auth.Model
{
    public class RegisterModel
    {

        [Required(ErrorMessage ="Username can't be null")]
        public string? Username { get; set; }
        [Required(ErrorMessage = "Email can't be null")]
        public string? Email { get; set; }
        [Required(ErrorMessage = "Password can't be null")]
        public string? Password { get; set; }
    }
}
