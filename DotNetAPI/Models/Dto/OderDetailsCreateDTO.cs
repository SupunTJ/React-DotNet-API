using System.ComponentModel.DataAnnotations;

namespace DotNetAPI.Models.Dto
{
    public class OderDetailsCreateDTO
    {


        [Required]
        public int MenuItemId { get; set; }

        [Required]
        public int Quantity { get; set; }
        [Required]
        public string ItemName { get; set; }
        [Required]
        public double Price { get; set; }
    }
}
