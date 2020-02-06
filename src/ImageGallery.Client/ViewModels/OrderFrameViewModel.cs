namespace ImageGallery.Client.ViewModels
{
    public class OrderFrameViewModel
    {
        public string Address { get; set; }

        public OrderFrameViewModel(string address)
        {
            Address = address;
        }
    }
}
