import PropTypes from "prop-types";
import React, {useEffect, useState} from "react";
import Logo from "./Logo";
import NavMenu from "./NavMenu";
import IconGroup from "./IconGroup";
import MobileMenu from "./MobileMenu";

const Header = ({
                    layout,
                    headerPaddingClass,
                    headerPositionClass,
                    headerBgClass
                }: any) => {
    const [scroll, setScroll] = useState(0);
    const [headerTop, setHeaderTop] = useState(0);

    useEffect(() => {
        const header: any = document.querySelector(".sticky-bar");
        setHeaderTop(header.offsetTop);
        window.addEventListener("scroll", handleScroll);
        return () => {
            window.removeEventListener("scroll", handleScroll);
        };
    }, []);

    const handleScroll = () => {
        setScroll(window.scrollY);
    };

    return (
        <header
            className={`header-area clearfix ${headerBgClass ? headerBgClass : ""} ${
                headerPositionClass ? headerPositionClass : ""
            }`}>
            <div
                className={` ${headerPaddingClass ? headerPaddingClass : ""} sticky-bar header-res-padding clearfix ${scroll > headerTop ? "stick" : ""}`}>
                <div className={layout === "container-fluid" ? layout : "container"}>
                    <div className="row">
                        <div className="col-xl-2 col-lg-2 col-md-6 col-4">
                            <Logo imageUrl="/assets/logomain.png" logoClass="logo"/>
                        </div>
                        <div className="col-xl-8 col-lg-8 d-none d-lg-block">
                            <NavMenu/>
                        </div>
                        <div className="col-xl-2 col-lg-2 col-md-6 col-8">
                            <IconGroup/>
                        </div>
                    </div>
                </div>
                <MobileMenu/>
            </div>
        </header>
    );
};

Header.propTypes = {
    borderStyle: PropTypes.string,
    headerPaddingClass: PropTypes.string,
    headerPositionClass: PropTypes.string,
    layout: PropTypes.string,
    top: PropTypes.string
};

export default Header;
