using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Pronia.Models
{
    public class AnotherSetting
    {
        public int Id { get; set; }
        public string HeaderLogo { get; set; }
        public string FooterLogo { get; set; }
        public string SearchIcon { get; set; }
        public string AccountIcon { get; set; }
        public string WishListIcon { get; set; }
        public string BasketIcon { get; set; }
        public string Phone { get; set; }
        public string AdvertisementImage { get; set; }
        public List<SocialMedia> SocialMedias { get; set; }
    }
}
