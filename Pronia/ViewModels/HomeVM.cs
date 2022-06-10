using Pronia.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Pronia.ViewModels
{
    public class HomeVM
    {
        public List<Slider> Sliders { get; set; }
        public List<Client> Clients { get; set; }
        public List<Plant> Plants { get; set; }
        public List<Category> Categories { get; set; }
        public AnotherSetting AnotherSetting { get; set; }

    }
}
