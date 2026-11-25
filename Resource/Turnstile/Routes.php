<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Resource\Turnstile;
final class Routes
{
    public const MAP=[
        'ps_turnstile_visit'=>'visit',
        'mypage_login'=>'customer_login','admin_login'=>'staff_login',
        'ps_customer_registration_resend'=>'entry','entry'=>'entry','entry_confirm'=>'entry','contact'=>'contact','contact_confirm'=>'contact',
        'forgot'=>'password_reset','forgot_reset'=>'password_reset',
        'ps_customer'=>'customer_security','ps_member'=>'staff_security',
        'ps_staff_password_reset'=>'staff_recovery','ps_staff_password_confirm'=>'staff_recovery','ps_staff_initial_request'=>'staff_recovery',
        'ps_staff_initial_link'=>'staff_mail','ps_staff_initial_email'=>'staff_mail','ps_staff_email_confirm'=>'staff_mail','ps_staff_email_manage'=>'staff_mail',
        'mypage_change'=>'account','mypage_delivery_new'=>'account','mypage_delivery_edit'=>'account',
        'mypage_withdraw'=>'account','mypage_withdraw_confirm'=>'account',
        'shopping_customer'=>'checkout','shopping_nonmember'=>'checkout','shopping_confirm'=>'checkout','shopping_checkout'=>'checkout',
        'shopping_redirect_to'=>'checkout','shopping_shipping'=>'checkout','shopping_shipping_edit'=>'checkout',
    ];
}
