using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using Pronia.DAL;
using Pronia.Models;
using Pronia.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Pronia.Services
{
    public class LayoutService
    {
        private readonly AppDbContext _context;
        private readonly IHttpContextAccessor httpContext;

        public LayoutService(AppDbContext context,IHttpContextAccessor _httpContext)
        {
            _context = context;
            httpContext = _httpContext;
        }
        public async Task<AnotherSetting> GetDatas()
        {
            //Task<List<Task>>
            // list<Setting> settings + tolistAsync

            AnotherSetting anothersetting = await _context.AnotherSettings.FirstOrDefaultAsync();
            return anothersetting;
        }
        public async Task<BasketVM> GetBasket()
        {
            string basketStr = httpContext.HttpContext.Request.Cookies["Basket"];
            BasketVM basketData = new BasketVM();
            if (!string.IsNullOrEmpty(basketStr))
            {
                
                List<BasketCookieItemVM> basket = JsonConvert.DeserializeObject<List<BasketCookieItemVM>>(basketStr);

                //List<Plant> query = await _context.Plants.Include(p=>p.PlantImages).ToListAsync();

                var query = _context.Plants.Include(p => p.PlantImages).AsQueryable();
                foreach (BasketCookieItemVM item in basket)
                {
                    Plant existedPlant =  query.FirstOrDefault(p => p.Id == item.Id);
                    if (existedPlant != null)
                    {
                        BasketItemVM basketItem = new BasketItemVM
                        {
                            Plant = existedPlant,
                            Count = item.Count
                        };
                        basketData.BasketItemVMs.Add(basketItem);
                       
                    }
                }
                
                decimal total = default;
                foreach (BasketItemVM item in basketData.BasketItemVMs)
                {
                    total += item.Plant.Price * item.Count;
                }
                basketData.TotalPrice = total;
                basketData.Count = basketData.BasketItemVMs.Count;
                return basketData;
                
                

            }
            else
            {
                return null;    
            }
        }
        
    }
}
