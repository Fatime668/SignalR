using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace Pronia.Models
{
    public class Slider
    {
        public int Id { get; set; }
        public string Image { get; set; }
        [StringLength(maximumLength:30)]
        public string Title { get; set; }
        public string SubTitle { get; set; }
        public byte Discount { get; set; }
        public byte Order { get; set; }
        public string DiscoverUrl { get; set; }
        [NotMapped]
        public IFormFile Photo { get; set; }
    }
}
