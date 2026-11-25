<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\EventSubscriber;

use Eccube\Event\TemplateEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

final class NavigationSubscriber implements EventSubscriberInterface
{
    public function __construct(private \Plugin\PasskeySecurity\Resource\Runtime\Config $compatibility) {}

    public static function getSubscribedEvents(): array
    {
        return ['@admin/login.twig'=>'link', 'Mypage/login.twig'=>'link', 'Mypage/navi.twig'=>'customerMenu', 'Forgot/index.twig'=>'link','Entry/index.twig'=>'entry','Entry/confirm.twig'=>'entry','Entry/complete.twig'=>'entry','Entry/activate.twig'=>'entry'];
    }
    public function entry(TemplateEvent $event): void
    {
        if (!$this->compatibility->shopEditionActive()) return;
        if ($event->getView()==='Entry/complete.twig') { $event->setSource("{% extends '@PasskeySecurity/entry_pending.twig' %}"); return; }
        if ($event->getView()==='Entry/activate.twig') { $event->setSource("{% extends '@PasskeySecurity/entry_activated.twig' %}"); return; }
        $source=$event->getSource();
        if (str_contains($source,'@PasskeySecurity/entry_intro.twig')) return;
        $source=preg_replace('/({%\s*block\s+main\s*%})/', '$1'."\n{% include '@PasskeySecurity/entry_intro.twig' %}\n",$source,1);
        if ($event->getView()==='Entry/index.twig') $source=str_replace("{{ '同意する'|trans }}","{{ '確認画面へ進む'|trans }}",$source);
        else $source=str_replace("{{ '会員登録をする'|trans }}","{{ BaseInfo.option_customer_activate ? '確認メールを送って仮登録する' : '会員登録を完了する' }}",$source);
        $event->setSource($source);
    }
    public function customerMenu(TemplateEvent $event): void
    {
        if (!$this->compatibility->shopEditionActive()) return;
        // The shared menu is rendered by all My Page screens, including change.twig.
        // Keep the clean core template and other plugins' menu entries intact.
        $source = $event->getSource();
        if (str_contains($source, '@PasskeySecurity/customer_menu_item.twig')) return;
        $source = preg_replace_callback(
            '~(<ul\b[^>]*class=["\'][^"\']*ec-navlistRole__navlist[^"\']*["\'][^>]*>)(.*?)(</ul>)~s',
            static fn(array $m): string => $m[1].$m[2]."\n{% include '@PasskeySecurity/customer_menu_item.twig' %}\n".$m[3],
            $source, 1, $count
        );
        if (is_string($source) && $count === 1) {
            $event->setSource($source."\n{% include '@PasskeySecurity/customer_menu_help.twig' %}\n");
        }
    }
    public function link(TemplateEvent $event): void
    {
        if (!$this->compatibility->shopEditionActive()) return;
        $event->setParameter('ps_navigation_member', str_starts_with($event->getView(), '@admin/'));
        $event->setParameter('ps_navigation_email_help',in_array($event->getView(), ['Mypage/login.twig','Forgot/index.twig'],true));
        $event->setParameter('ps_navigation_login',$event->getView()==='Mypage/login.twig');
        $source = preg_replace('/({%\s*block\s+main\s*%})/', '$1'."\n{% include '@PasskeySecurity/link.twig' %}\n", $event->getSource(), 1);
        if (is_string($source)) {
            if ($event->getView()==='Mypage/login.twig') $source=str_replace("{% include '@PasskeySecurity/link.twig' %}","{% include '@PasskeySecurity/link.twig' %}\n{% include '@PasskeySecurity/entry_login_help.twig' %}",$source);
            if ($event->getView()==='Mypage/login.twig') $source=str_replace('{% if BaseInfo.option_remember_me %}','{% if false %}',$source);
            $event->setSource($source);
        }
    }
}
