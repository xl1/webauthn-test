using PeterO.Cbor;

namespace Webauthntest.Models
{
    public static class CBORObjectExtention
    {
        public static CBORObject MapGet(this CBORObject obj, object key)
        {
            return obj[CBORObject.FromObject(key)];
        }
    }
}
