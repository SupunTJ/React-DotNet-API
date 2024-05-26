using Microsoft.AspNetCore.Identity;

namespace DotNetAPI.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string Name { get; set; }
    }
}
