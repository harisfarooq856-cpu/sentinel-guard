using System;
using System.Media;
using SentinelGuard.Models;

namespace SentinelGuard.Services
{
    public class NotificationService
    {
        public bool SoundEnabled { get; set; } = true;
        public bool ToastsEnabled { get; set; } = true;

        public void Alert(SecurityEvent ev)
        {
            if (SoundEnabled)
            {
                if (ev.Risk == RiskLevel.CRITICAL)
                    SystemSounds.Hand.Play();
                else if (ev.Risk == RiskLevel.HIGH)
                    SystemSounds.Exclamation.Play();
            }
        }
    }
}
